<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Database\CiphertextWrite;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Keys\ClientAssertionKeys;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Metadata\ProviderKeys;
use SineMacula\Laravel\Sso\Metadata\SamlRefreshRule;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Protocols\Preset;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;

/**
 * Creates, updates, reads, lists and enables a tenant's connections.
 *
 * Another tenant's connection is answered exactly as an unknown one.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConnectionService
{
    /** @var int The longest display name, in characters. */
    public const int MAX_DISPLAY_NAME_LENGTH = 255;

    /** @var string The display name, as a change and a violation name it. */
    private const string DISPLAY_NAME = 'display_name';

    /** @var string The settings, as a change names them. */
    private const string SETTINGS = 'settings';

    /** @var string The attribute mapping, as a change and a violation name it. */
    private const string ATTRIBUTE_MAPPING = 'attribute_mapping';

    /** @var string The preset, as a violation names it. */
    private const string PRESET = 'preset';

    /** @var string The column of the encrypted secrets. */
    private const string SECRETS = 'secrets';

    /** @var string The failure of a write of the encrypted secrets. */
    private const string SECRETS_NOT_WRITTEN = 'The connection\'s secrets could not be written';

    /** @var list<string> What a change may never name, being fixed at creation. */
    private const array FIXED = ['tenant_id', 'protocol'];

    /** @var array<string, null> What an update gives for each change it leaves out. */
    private const array NO_CHANGES = [self::SETTINGS => null, self::ATTRIBUTE_MAPPING => null, self::DISPLAY_NAME => null];

    /** @var list<\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation> What a subject migration also asks. */
    private const array MIGRATION_OPERATIONS = [FreshnessOperation::CONNECTION_TRUST, FreshnessOperation::LINK_REMOVE];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $finder
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionSecrets  $secrets
     * @param  \SineMacula\Laravel\Sso\Administration\AdministrationEvents  $events
     * @param  \SineMacula\Laravel\Sso\Connections\MappingLimits  $limits
     * @param  \SineMacula\Laravel\Sso\Connections\InFlightVoider  $voider
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The protocol drivers and presets. */
        private ProtocolManager $protocols,

        /** The tenant-scoped lookup, on the write connection. */
        private ConnectionFinder $finder,

        /** The freshness contract every change asks first. */
        private FreshnessGate $freshness,

        /** The connections' encrypted secrets. */
        private ConnectionSecrets $secrets,

        /** The reporter of every change. */
        private AdministrationEvents $events,

        /** The caps on what an attribute mapping carries. */
        private MappingLimits $limits,

        /** Voids what a trust change leaves in flight. */
        private InFlightVoider $voider,

        /** The clock a link reservation's expiry is judged against. */
        private Clock $clock,
    ) {}

    /**
     * Create a disabled connection; what is given overrides the preset, which
     * overrides the protocol's default mapping.
     *
     * @param  string  $tenantId
     * @param  string  $protocol
     * @param  string  $displayName
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributeMapping
     * @param  ?string  $preset
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     *
     * @SuppressWarnings("php:S107")
     */
    public function create(
        string $tenantId,
        string $protocol,
        string $displayName,
        ClientContext $client,
        #[\SensitiveParameter] array $settings = [],
        array $attributeMapping = [],
        ?string $preset = null,
        ?Caller $caller = null,
    ): ConnectionResult {
        self::assertTenant($tenantId);

        $chosen  = $preset === null ? null : $this->protocols->preset($preset);
        $refusal = $this->refusalToCreate($protocol, $preset, $chosen);

        if ($refusal !== null) {
            return $refusal;
        }

        $secretNames = $this->secretNamesOf($protocol);
        $values      = self::keyed($chosen?->fill($settings) ?? $settings, true);
        $given       = array_intersect_key($values, array_flip($secretNames));
        $values      = array_diff_key($values, $given);
        $mapping     = self::keyed(array_replace(AttributeMapping::defaults($protocol), $chosen?->fillMapping($attributeMapping) ?? $attributeMapping), true);
        $name        = trim($displayName);
        $typed       = $this->protocols->protocol($protocol)->settings($values);
        $map         = AttributeMapping::fromArray($protocol, $mapping, $this->limits);

        $violations = [
            ...SettingRules::at(self::DISPLAY_NAME, self::displayName($name)),
            ...$typed->violations(),
            ...ConnectionSecrets::violations($typed, $secretNames, $given),
            ...$map->violations(),
        ];

        if ($violations !== []) {
            return ConnectionResult::invalid($violations);
        }

        $operations = self::operations($typed, [...array_keys($values), ...array_keys($given)], [FreshnessOperation::CONNECTION_TRUST]);

        return $this->transaction(function () use ($tenantId, $protocol, $name, $typed, $given, $map, $operations, $client, $caller): ConnectionResult {

            $refusal = $this->staleRefusal($operations, $caller);

            if ($refusal !== null) {
                return $refusal;
            }

            $connection = new Connection;

            $connection->forceFill([
                'tenant_id'         => $tenantId,
                'protocol'          => $protocol,
                'display_name'      => $name,
                'settings'          => $typed->toArray(),
                'secrets'           => $this->secrets->apply(null, ConnectionSecrets::changes($given)),
                'attribute_mapping' => $map->toArray(),
                'enabled'           => false,
            ]);

            CiphertextWrite::save($connection, self::SECRETS, self::SECRETS_NOT_WRITTEN);

            $this->events->connectionCreated($connection, $caller, $client);

            return ConnectionResult::created($this->summary($connection));
        });
    }

    /**
     * Merge the changes, where `null` removes a value, and validate the result
     * as a whole; only what changed asks for freshness.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  array<string, mixed>  $changes
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function update(string $tenantId, string $connectionId, #[\SensitiveParameter] array $changes, ClientContext $client, ?Caller $caller = null): ConnectionResult
    {
        self::assertTenant($tenantId);

        return $this->transaction(function () use ($tenantId, $connectionId, $changes, $client, $caller): ConnectionResult {

            $connection = $this->finder->findForUpdate($tenantId, $connectionId);

            if ($connection === null || !$this->protocols->isAvailable($connection->protocol)) {
                return ConnectionResult::refused($connection === null ? FailureReason::CONNECTION_NOT_FOUND : FailureReason::PROTOCOL_UNAVAILABLE);
            }

            return $this->changeLocked($connection, $changes, $client, $caller);
        });
    }

    /**
     * The tenant's connection with the id, or `null` when it has none.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return ?\SineMacula\Laravel\Sso\Connections\ConnectionSummary
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    public function get(string $tenantId, string $connectionId): ?ConnectionSummary
    {
        $connection = $this->finder->find($tenantId, $connectionId);

        return $connection === null ? null : $this->summary($connection);
    }

    /**
     * Every connection of the tenant, oldest first.
     *
     * @param  string  $tenantId
     * @return list<\SineMacula\Laravel\Sso\Connections\ConnectionSummary>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    public function list(string $tenantId): array
    {
        return array_map($this->summary(...), $this->finder->forTenant($tenantId));
    }

    /**
     * Freshness is asked even when already enabled; settings need not be
     * complete, since an incomplete connection is never usable.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function enable(string $tenantId, string $connectionId, ClientContext $client, ?Caller $caller = null): ConnectionResult
    {
        self::assertTenant($tenantId);

        return $this->transaction(function () use ($tenantId, $connectionId, $client, $caller): ConnectionResult {

            $connection = $this->finder->findForUpdate($tenantId, $connectionId);

            if ($connection === null || !$this->protocols->isAvailable($connection->protocol)) {
                return ConnectionResult::refused($connection === null ? FailureReason::CONNECTION_NOT_FOUND : FailureReason::PROTOCOL_UNAVAILABLE);
            }

            $refusal = $this->staleRefusal([FreshnessOperation::CONNECTION_ENABLE], $caller);

            if ($refusal !== null || $connection->enabled) {
                return $refusal ?? ConnectionResult::unchanged($this->summary($connection));
            }

            $connection->forceFill(['enabled' => true, 'trust_version' => $connection->trust_version + 1])->save();

            $this->events->connectionEnabled($connection, $caller, $client);

            return ConnectionResult::enabled($this->summary($connection));
        });
    }

    /**
     * The body of `update()` under the caller's lock; non-null
     * `$relinkViolations` marks a subject migration.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, mixed>  $changes
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  ?list<\SineMacula\Laravel\Sso\Connections\SettingViolation>  $relinkViolations
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \RuntimeException
     * @throws \JsonException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     *
     * @internal
     */
    public function changeLocked(
        Connection $locked,
        #[\SensitiveParameter] array $changes,
        ClientContext $client,
        ?Caller $caller = null,
        ?array $relinkViolations = null,
    ): ConnectionResult {
        $asked           = $changes + self::NO_CHANGES;
        $migrating       = $relinkViolations !== null;
        $secretNames     = $this->secretNamesOf($locked->protocol);
        $given           = self::keyed($asked[self::SETTINGS]);
        $secrets         = array_intersect_key($given, array_flip($secretNames));
        $values          = self::merged($locked->settings, array_diff_key($given, $secrets));
        $name            = is_string($asked[self::DISPLAY_NAME]) ? trim($asked[self::DISPLAY_NAME]) : $locked->display_name;
        $typed           = $this->protocols->protocol($locked->protocol)->settings($values);
        $map             = AttributeMapping::fromArray($locked->protocol, self::merged($locked->attribute_mapping, self::keyed($asked[self::ATTRIBUTE_MAPPING])), $this->limits);
        $stored          = $typed->toArray();
        $changedSettings = self::changedSettings($typed, $locked->settings, $stored);
        $changedSecrets  = ConnectionSecrets::changedNames($secretNames, $secrets, $this->secrets->names($locked));
        $operations      = self::operations($typed, [...$changedSettings, ...$changedSecrets], $migrating ? self::MIGRATION_OPERATIONS : []);

        $violations = [
            ...self::changeViolations($changes),
            ...SettingRules::at(self::DISPLAY_NAME, self::displayName($name)),
            ...$typed->violations(),
            ...ConnectionSecrets::violations($typed, $secretNames, $secrets),
            ...$map->violations(),
            ...(array) $relinkViolations,
            ...ClientAssertionKeys::changeViolations($locked, $stored, $changedSettings),
        ];

        $fields = array_filter([
            self::DISPLAY_NAME      => $name !== $locked->display_name,
            self::ATTRIBUTE_MAPPING => !SettingRules::isSame($map->toArray(), $locked->attribute_mapping),
        ]);
        $changed = [...$changedSettings, ...$changedSecrets, ...array_keys($fields), ...LinkingPolicyReset::changedNames($locked, $typed, $changedSettings)];

        $refusal = match (true) {
            $violations !== [] => ConnectionResult::invalid($violations),
            $changed === []    => ConnectionResult::unchanged($this->summary($locked)),
            default            => $this->staleRefusal($operations, $caller) ?? $this->linkedRefusal($typed, $changedSettings, $locked, $migrating),
        };

        if ($refusal !== null) {
            return $refusal;
        }

        $locked->forceFill([
            'display_name'      => $name,
            'settings'          => $stored,
            'secrets'           => $this->secrets->apply($locked->secrets, ConnectionSecrets::changes($secrets)),
            'attribute_mapping' => $map->toArray(),
            ...ProviderKeys::resetFor($locked, $changedSettings, $stored),
            ...SamlRefreshRule::resetForSettings($locked, $changedSettings, $stored),
            ...LinkingPolicyReset::of($locked, $typed, $changedSettings),
        ]);

        CiphertextWrite::save($locked, self::SECRETS, self::SECRETS_NOT_WRITTEN);

        if (in_array(FreshnessOperation::CONNECTION_TRUST, $operations, true)) {
            $this->voider->voidFor($locked);
        }

        $this->events->connectionUpdated($locked, $changed, $caller, $client);

        return ConnectionResult::updated($this->summary($locked), $changed);
    }

    /**
     * The connection's summary.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSummary
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    private function summary(Connection $connection): ConnectionSummary
    {
        return ConnectionSummary::of($connection, $this->protocols, $this->secrets);
    }

    /**
     * Why a connection cannot be created over the protocol with the preset, or
     * `null`.
     *
     * @param  string  $protocol
     * @param  ?string  $preset
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Preset  $chosen
     * @return ?\SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     */
    private function refusalToCreate(string $protocol, ?string $preset, ?Preset $chosen): ?ConnectionResult
    {
        if (!$this->protocols->isAvailable($protocol)) {
            return ConnectionResult::refused(FailureReason::PROTOCOL_UNAVAILABLE);
        }

        $code = match (true) {
            $preset === null                => null,
            $chosen === null                => ViolationCode::UNKNOWN,
            $chosen->protocol !== $protocol => ViolationCode::NOT_ALLOWED,
            default                         => null,
        };

        return $code === null ? null : ConnectionResult::invalid([new SettingViolation(self::PRESET, $code)]);
    }

    /**
     * `freshness_required` unless the caller is fresh for every operation.
     *
     * @param  list<\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation>  $operations
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return ?\SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function staleRefusal(array $operations, ?Caller $caller): ?ConnectionResult
    {
        return $this->freshness->checkAll($operations, $caller)->isFresh() ? null : ConnectionResult::refused(FailureReason::FRESHNESS_REQUIRED);
    }

    /**
     * `connection_has_links` for a subject setting change outside a migration
     * while any held or unexpired reserved link exists.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\ProtocolSettings  $settings
     * @param  list<string>  $changedSettings
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  bool  $migrating
     * @return ?\SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     */
    private function linkedRefusal(ProtocolSettings $settings, array $changedSettings, Connection $locked, bool $migrating): ?ConnectionResult
    {
        if ($migrating || array_intersect($changedSettings, $settings::subjectNames()) === []) {
            return null;
        }

        $query = Link::query();
        $now   = UtcDateTime::format($query->getModel(), $this->clock->now());

        $link = $query->useWritePdo()
            ->where('connection_id', $locked->id)
            ->where(static function (Builder $held) use ($now): void {
                $held->whereIn('state', [LinkState::ACTIVE->value, LinkState::SUSPENDED->value])->orWhere(static function (Builder $reserved) use ($now): void {
                    $reserved->where('state', LinkState::RESERVED->value)->where('reservation_expires_at', '>', $now);
                });
            })
            ->lockForUpdate()
            ->first();

        return $link === null ? null : ConnectionResult::refused(FailureReason::CONNECTION_HAS_LINKS);
    }

    /**
     * The names of the secrets the protocol's settings declare.
     *
     * @param  string  $protocol
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function secretNamesOf(string $protocol): array
    {
        return $this->protocols->protocol($protocol)->settings([])::secretNames();
    }

    /**
     * Run the callback in one transaction on the storage connection.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Connections\ConnectionResult  $callback
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function transaction(\Closure $callback): ConnectionResult
    {
        return DB::connection(StorageConnection::name())->transaction($callback);
    }

    /**
     * Refuse a tenant id the connections table cannot hold.
     *
     * @param  string  $tenantId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertTenant(string $tenantId): void
    {
        if ($tenantId === '' || strlen($tenantId) > ConnectionFinder::MAX_TENANT_ID_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A tenant id is 1 to %d bytes.', ConnectionFinder::MAX_TENANT_ID_LENGTH));
        }
    }

    /**
     * Why the trimmed display name is refused, or `null`.
     *
     * @param  string  $name
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function displayName(string $name): ?ViolationCode
    {
        return match (true) {
            $name === ''                                              => ViolationCode::REQUIRED,
            mb_strlen($name, 'UTF-8') > self::MAX_DISPLAY_NAME_LENGTH => ViolationCode::TOO_LONG,
            !SettingRules::isPrintable($name)                         => ViolationCode::INVALID_FORMAT,
            default                                                   => null,
        };
    }

    /**
     * The problems with the keys of an update and their types.
     *
     * @param  array<array-key, mixed>  $changes
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function changeViolations(array $changes): array
    {
        $violations = [];

        foreach ($changes as $key => $value) {

            $code = match ($key) {
                self::DISPLAY_NAME                      => is_string($value) ? null : ViolationCode::INVALID_TYPE,
                self::SETTINGS, self::ATTRIBUTE_MAPPING => is_array($value) ? null : ViolationCode::INVALID_TYPE,
                default                                 => in_array($key, self::FIXED, true) ? ViolationCode::IMMUTABLE : ViolationCode::UNKNOWN,
            };

            array_push($violations, ...SettingRules::at(SettingRules::path(null, $key), $code));
        }

        return $violations;
    }

    /**
     * The settings whose stored value or presence changes, in the protocol's
     * setting order.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\ProtocolSettings  $settings
     * @param  array<string, mixed>  $before
     * @param  array<string, mixed>  $after
     * @return list<string>
     */
    private static function changedSettings(ProtocolSettings $settings, array $before, array $after): array
    {
        $order = match ($settings::class) {
            Saml2Settings::class => array_column(Saml2Setting::cases(), 'value'),
            OidcSettings::class  => array_column(OidcSetting::cases(), 'value'),
            default              => [],
        };

        $names = array_keys(array_replace($after, $before));
        $names = [...array_intersect($order, $names), ...array_diff($names, $order)];

        $changed = static fn (int|string $name): bool => !array_key_exists($name, $before)
            || !array_key_exists($name, $after)
            || !SettingRules::isSame($before[$name], $after[$name]);

        return array_values(array_filter($names, $changed));
    }

    /**
     * The operations the named changes need plus those given, deduplicated in
     * `FreshnessOperation` order.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\ProtocolSettings  $settings
     * @param  list<int|string>  $names
     * @param  list<\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation>  $operations
     * @return list<\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation>
     */
    private static function operations(ProtocolSettings $settings, array $names, array $operations = []): array
    {
        foreach ($names as $name) {
            $operations[] = $settings::freshnessFor((string) $name);
        }

        return array_values(array_filter(FreshnessOperation::cases(), static fn (FreshnessOperation $operation): bool => in_array($operation, $operations, true)));
    }

    /**
     * The stored values with the changes merged in; `null` removes one.
     *
     * @param  array<string, mixed>  $stored
     * @param  array<string, mixed>  $changes
     * @return array<string, mixed>
     */
    private static function merged(array $stored, #[\SensitiveParameter] array $changes): array
    {
        foreach ($changes as $name => $value) {

            if ($value === null) {
                unset($stored[$name]);
                continue;
            }

            $stored[$name] = $value;
        }

        return $stored;
    }

    /**
     * The value as a string-keyed map, empty when it is not an array.
     *
     * @param  mixed  $values
     * @param  bool  $withoutNulls
     * @return array<string, mixed>
     */
    private static function keyed(#[\SensitiveParameter] mixed $values, bool $withoutNulls = false): array
    {
        $map = [];

        foreach (is_array($values) ? $values : [] as $name => $value) {

            if ($withoutNulls && $value === null) {
                continue;
            }

            $map[(string) $name] = $value;
        }

        return $map;
    }
}
