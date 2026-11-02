<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Database\CiphertextWrite;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Keys\ClientAssertionKeys;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Metadata\ProviderKeys;
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
 * The management helpers that create, update, read, list and enable a tenant's
 * connections (SSO-1.2, SSO-2.11), for the application's own administration
 * screens: who may call them is the application's authorisation, never the
 * package's.
 *
 * Every helper is scoped to a tenant, an opaque id of 1 to 255 bytes: another
 * tenant's connection is answered exactly as an unknown one. A change follows
 * one order: find the connection, locked, on the write connection; refuse an
 * unavailable protocol; validate what was given, as a whole; ask the freshness
 * contract with each operation the change is (SSO-2.12); then write through the
 * model, in one transaction on the storage connection, and report the change
 * through `Administration\AdministrationEvents` inside it. A refusal at any
 * step is a `ConnectionResult` that wrote and reported nothing; a change that
 * changes nothing succeeds as `unchanged`, writes nothing and reports nothing.
 * An update that changes nothing asks nothing, while enabling an enabled
 * connection still asks freshness. A database error and a `SecretEncrypter`
 * that cannot encrypt propagate (SSO-11.4); a failed write of the encrypted
 * secrets propagates as a `RuntimeException` that quotes none of them; an empty
 * or overlong tenant id is an `InvalidArgumentException`.
 *
 * Secrets are taken out of the settings by the protocol's `secretNames()`, each
 * a string of 1 to 1024 bytes with no control character, encrypted on its own,
 * never returned and kept when an update does not name it (SSO-2.5). Every
 * parameter that carries what an administrator gave, secrets among it, is
 * `#[\SensitiveParameter]`, so an exception's trace shows none of it. A map
 * given again in another key order, such as `extra_parameters`, is not a
 * change: maps are compared whatever their key order, lists in order. A new
 * connection is disabled; enabling one needs no complete settings, since only a
 * complete connection is ever usable.
 *
 * A change to a setting the protocol's `subjectNames()` lists (the issuer or
 * entity id, the client id, the subject source, the NameID format) may change
 * what the connection's existing subjects mean, so an update making one is
 * refused with `connection_has_links` while the connection has a link, active
 * or reserved until after now, read with a locking read once freshness has been
 * asked; `Connections\SubjectMigration` makes such a change and relinks or
 * removes the links with it (SSO-2.13). Every update that asks
 * `sso.connection.trust` voids, in its transaction and under the connection's
 * lock, the requests and handoff codes in flight through the connection
 * (`Connections\InFlightVoider`) and raises its trust version; a change that
 * asks only another operation, or none, voids nothing. Enabling a connection
 * raises its trust version too, under its lock. An update of an OIDC
 * connection's `issuer` or `jwks_uri` also clears, in the same save, the keys
 * fetched for it and their cooldown, and for an `issuer` the discovery
 * document's refresh dates too (`Metadata\ProviderKeys::resetFor()`), so keys
 * fetched for another issuer or URL are never used; so does an endpoint changed
 * with `metadata_refresh` off clear when the document was last validated, since
 * the endpoints are then saved by hand. A change of an OIDC connection's
 * `client_assertion_algorithm` is refused as `unsupported` when its current or
 * next key cannot sign under it (`Keys\ClientAssertionKeys`), read under the
 * lock, and is a trust change like any other.
 *
 * It holds the registry, the lookup, the freshness gate, the secrets, the
 * reporter, the mapping's caps, the voider and the clock, none of which keeps
 * anything of one request for the next (SSO-11.2). Resolve it from the
 * container per request.
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

    /** @var string The failure of a write of the encrypted secrets, which names none of them. */
    private const string SECRETS_NOT_WRITTEN = 'The connection\'s secrets could not be written';

    /** @var list<string> What a change may never name: a connection's tenant and protocol are fixed (SSO-2.1). */
    private const array FIXED = ['tenant_id', 'protocol'];

    /** @var array<string, null> What an update gives for each change it leaves out. */
    private const array NO_CHANGES = [self::SETTINGS => null, self::ATTRIBUTE_MAPPING => null, self::DISPLAY_NAME => null];

    /** @var list<\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation> What a subject migration asks besides what its change asks. */
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
     * Create a connection for the tenant, disabled, over the protocol: its
     * display name, its settings (secrets among them, by name), its attribute
     * mapping over the protocol's defaults, and optionally a preset of the
     * protocol, whose settings and mapping what is given replaces.
     *
     * A setting or mapping target given as `null` is not set. Refused with
     * `protocol_unavailable` when the protocol is not registered or its feature
     * is off, `settings_invalid` with every violation, or `freshness_required`
     * when the caller's authentication is not fresh enough for a trust change
     * and each operation a setting given needs.
     *
     * @param  string  $tenantId
     * @param  string  $protocol
     * @param  string  $displayName
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributeMapping
     * @param  ?string  $preset
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function create(
        string $tenantId,
        string $protocol,
        string $displayName,
        #[\SensitiveParameter] array $settings = [],
        array $attributeMapping = [],
        ?string $preset = null,
        ?ActingIdentity $actor = null,
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

        $refusal = $violations === []
            ? $this->staleRefusal(self::operations($typed, [...array_keys($values), ...array_keys($given)], [FreshnessOperation::CONNECTION_TRUST]))
            : ConnectionResult::invalid($violations);

        return $refusal ?? $this->transaction(function () use ($tenantId, $protocol, $name, $typed, $given, $map, $actor): ConnectionResult {

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

            $this->events->connectionCreated($connection, $actor);

            return ConnectionResult::created($this->summary($connection));
        });
    }

    /**
     * Change the tenant's connection: its `display_name`, its `settings` (a
     * setting given replaces the stored one and `null` removes it; a secret
     * given as a string sets it, as `null` clears it, and one not given is
     * kept) and its `attribute_mapping` (a target given replaces the stored one
     * and `null` removes it).
     *
     * The merged connection is validated as a whole, as `create()` validates a
     * new one; a change to `tenant_id` or `protocol` is `immutable`, and any
     * other key `unknown`. Only what changed asks for freshness, and only a
     * change that changed something is written and reported, naming each
     * setting, secret, `display_name` or `attribute_mapping` that changed. A
     * change to a subject setting of a connection with links is refused with
     * `connection_has_links`, and a trust change voids what is in flight.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  array<string, mixed>  $changes
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function update(string $tenantId, string $connectionId, #[\SensitiveParameter] array $changes, ?ActingIdentity $actor = null): ConnectionResult
    {
        self::assertTenant($tenantId);

        return $this->transaction(function () use ($tenantId, $connectionId, $changes, $actor): ConnectionResult {

            $connection = $this->finder->findForUpdate($tenantId, $connectionId);

            if ($connection === null || !$this->protocols->isAvailable($connection->protocol)) {
                return ConnectionResult::refused($connection === null ? FailureReason::CONNECTION_NOT_FOUND : FailureReason::PROTOCOL_UNAVAILABLE);
            }

            return $this->changeLocked($connection, $changes, $actor);
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
     * Enable the tenant's connection. Freshness is asked even when it is
     * enabled already, which then succeeds as `unchanged`. Its settings need
     * not be complete: an incomplete connection is never usable.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function enable(string $tenantId, string $connectionId, ?ActingIdentity $actor = null): ConnectionResult
    {
        self::assertTenant($tenantId);

        return $this->transaction(function () use ($tenantId, $connectionId, $actor): ConnectionResult {

            $connection = $this->finder->findForUpdate($tenantId, $connectionId);

            if ($connection === null || !$this->protocols->isAvailable($connection->protocol)) {
                return ConnectionResult::refused($connection === null ? FailureReason::CONNECTION_NOT_FOUND : FailureReason::PROTOCOL_UNAVAILABLE);
            }

            $refusal = $this->staleRefusal([FreshnessOperation::CONNECTION_ENABLE]);

            if ($refusal !== null || $connection->enabled) {
                return $refusal ?? ConnectionResult::unchanged($this->summary($connection));
            }

            $connection->forceFill(['enabled' => true, 'trust_version' => $connection->trust_version + 1])->save();

            $this->events->connectionEnabled($connection, $actor);

            return ConnectionResult::enabled($this->summary($connection));
        });
    }

    /**
     * Merge the changes into the locked connection, validate the result, and
     * write and report what changed: what `update()` does once it has found the
     * connection, locked, and refused an unavailable protocol.
     *
     * `Connections\SubjectMigration` alone passes the violations of its relinks
     * (none when every relink is valid). They are reported after the change's
     * own; freshness is asked with `sso.connection.trust` and `sso.link.remove`
     * besides what the change asks; and a change to a subject setting is not
     * refused for the connection's links, which the migration relinks or
     * removes in the same transaction. The caller holds the connection's lock
     * in its transaction on the storage connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, mixed>  $changes
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
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
    public function changeLocked(Connection $locked, #[\SensitiveParameter] array $changes, ?ActingIdentity $actor = null, ?array $relinkViolations = null): ConnectionResult
    {
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

        $changed = [...$changedSettings, ...$changedSecrets, ...array_keys($fields)];

        $refusal = match (true) {
            $violations !== [] => ConnectionResult::invalid($violations),
            $changed === []    => ConnectionResult::unchanged($this->summary($locked)),
            default            => $this->staleRefusal($operations) ?? $this->linkedRefusal($typed, $changedSettings, $locked, $migrating),
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
        ]);

        CiphertextWrite::save($locked, self::SECRETS, self::SECRETS_NOT_WRITTEN);

        if (in_array(FreshnessOperation::CONNECTION_TRUST, $operations, true)) {
            $this->voider->voidFor($locked);
        }

        $this->events->connectionUpdated($locked, $changed, $actor);

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
     * `null` when it can: the protocol is unavailable, or the preset is unknown
     * or of another protocol.
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
     * The refusal of a caller whose authentication is not fresh enough for
     * every operation, or `null` when it is, or none is given.
     *
     * @param  list<\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation>  $operations
     * @return ?\SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function staleRefusal(array $operations): ?ConnectionResult
    {
        return $this->freshness->checkAll($operations)->isFresh() ? null : ConnectionResult::refused(FailureReason::FRESHNESS_REQUIRED);
    }

    /**
     * The refusal of a change to a subject setting of a connection that has
     * links, or `null` when the change alters no subject, is a subject
     * migration's, which relinks or removes the links, or the connection has
     * none: an active link, or a reserved one whose reservation expires after
     * now, found by a locking read on the write connection.
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
                $held->where('state', LinkState::ACTIVE->value)->orWhere(static function (Builder $reserved) use ($now): void {
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
     * Refuse a tenant id the connections table cannot hold: the application's
     * mistake.
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
     * Why the trimmed display name is refused, or `null` when it is not: it is
     * 1 to 255 characters of valid UTF-8 with no control character.
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
     * The problems with the keys of an update: a fixed key is `immutable`, a
     * key that is not a change `unknown`, and a change of the wrong type
     * `invalid_type`.
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
     * The names of the settings whose stored value changes, presence included,
     * in the order the protocol names its settings. A map is compared whatever
     * its key order, so one given again in another order, or read back from a
     * native JSON column that orders keys its own way, is not a change.
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
     * The operations whose freshness a change to the names needs, with those
     * given, each once, in the order `FreshnessOperation` lists them.
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
     * The stored values with the changes merged in: a value given replaces the
     * stored one, and `null` removes it.
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
     * The map the value gives, keyed by name, leaving out each entry given as
     * `null` when asked to; none when the value is not a map.
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
