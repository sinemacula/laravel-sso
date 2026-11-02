<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Linking\DomainLinkEligibility;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\Results\LinkingEmail;

/**
 * The management helper for a connection's linking by a verified domain
 * (SSO-8.8, SSO-2.12, SSO-2.13), for the application's own administration
 * screens: who may call it is the application's authorisation, never the
 * package's. It is off by default, per connection.
 *
 * `change()` takes any of these, by name, and leaves what it does not name:
 *
 * - `enabled`: whether linking is on, `true` or `false`;
 * - `issuer_class`: `shared` or `single_organization`, or `null`;
 * - `organization_claim`: the claim, or for SAML the attribute's `Name`,
 *   telling a shared issuer's organisations apart, or `null`;
 * - `organization_value`: the value this connection's organisation holds there,
 *   compared exactly, or `null`;
 * - `saml_attribute` and `saml_attribute_format`: the exact `Name` and
 *   `NameFormat` of the one attribute a SAML connection reads the linking email
 *   from, or `null`; on another protocol they are `unsupported`;
 * - `acknowledged`: that the administrator states the provider decides which
 *   subject holds each of the domain's addresses, and for a single organisation
 *   that it is one, `true` or `false`.
 *
 * It goes in one order, as `ConnectionLifecycle` does, so nothing slow runs
 * under a lock:
 *
 * 1. the connection is found by a plain read on the write connection; none is
 *    `connection_not_found`;
 * 2. the freshness contract is asked with `sso.connection.trust`; `stale` is
 *    `freshness_required`;
 * 3. in one transaction on the storage connection, the connection's row is read
 *    again locked; gone is `connection_not_found`, and a protocol no longer
 *    available `protocol_unavailable`;
 * 4. what was given is judged, and, while the merged settings have linking on,
 *    the settings as a whole, on the locked row, with every violation answered
 *    as `settings_invalid`;
 * 5. a change of nothing is `unchanged`, and writes and reports nothing;
 * 6. the settings are written and `linking_version` raised by one;
 *    `Links\ReservationWithdrawal::ofConnection()` deletes the connection's
 *    open reservations, and `ConnectionUpdated` is reported after commit,
 *    naming what changed as `linking.*`, never a value.
 *
 * This is no protocol trust change: `trust_version` stays, and no request or
 * code is voided. A flow in flight goes on, but its response's linking evidence
 * no longer authorises a reservation, and a code bound to a reservation meets
 * `reservation_invalid`. A change that also alters protocol trust is
 * `ConnectionService`'s, which voids flows.
 *
 * Linking can be on only under the `domain_linking` feature (`unsupported` at
 * `enabled`), and with an explicit classification, since an unset one never
 * means single organisation (`required` at `issuer_class`). An issuer the
 * package knows to be shared (`DomainLinkEligibility::requiredClaim()`: what a
 * preset with an organisation claim names, or else what
 * `Linking\LinkingSettings` lists) can only be `shared` (`not_allowed` at
 * `issuer_class`) and only under that very claim (`not_allowed` at
 * `organization_claim`). Configuration may add such an issuer and never
 * downgrade one. A `shared` issuer needs its claim and value. A
 * `single_organization` issuer and any SAML connection need the
 * acknowledgement, recorded with its time. SAML needs the attribute's `Name`
 * and `NameFormat`. An acknowledgement stands for what it was given about:
 * changing the classification or the SAML attribute without giving it again
 * clears it. Changing the issuer itself is `ConnectionService`'s, which clears
 * the classification and the acknowledgement and turns linking off with it
 * (`LinkingPolicyReset`). On OIDC an organisation claim cannot be a protocol
 * value or a token (`AttributeMapping::RESERVED_OIDC_SOURCES`), nor the email
 * itself (`reserved`).
 *
 * Linking on over a bound `Contracts\Linker` not backed by
 * `Contracts\LinkStorage` is a `LogicException`, with nothing written: the
 * reservations it would make are rows the resolver ignores.
 *
 * The organisation's value is never logged, reported or echoed by a violation.
 * An empty or overlong tenant id is an `InvalidArgumentException`; a database
 * error propagates (SSO-11.4). It holds the lookup, the freshness gate, the
 * reporter, the registry, the secrets, the eligibility, the clock and the
 * storage binding, none of which keeps anything of one request for the next
 * (SSO-11.2). Resolve it from the container per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkingPolicyService
{
    /** @var string Whether linking is on, as a change names it. */
    private const string ENABLED = 'enabled';

    /** @var string The issuer's classification, as a change names it. */
    private const string ISSUER_CLASS = 'issuer_class';

    /** @var string The organisation claim, as a change names it. */
    private const string ORGANIZATION_CLAIM = 'organization_claim';

    /** @var string The organisation's expected value, as a change names it. */
    private const string ORGANIZATION_VALUE = 'organization_value';

    /** @var string The SAML attribute's `Name`, as a change names it. */
    private const string SAML_ATTRIBUTE = 'saml_attribute';

    /** @var string The SAML attribute's `NameFormat`, as a change names it. */
    private const string SAML_ATTRIBUTE_FORMAT = 'saml_attribute_format';

    /** @var string The administrator's acknowledgement, as a change names it. */
    private const string ACKNOWLEDGED = 'acknowledged';

    /** @var string What `ConnectionUpdated` names each change under. */
    private const string CHANGED_PREFIX = 'linking.';

    /** @var array<string, string> The column each setting is stored in, but for the acknowledgement. */
    private const array COLUMNS = [
        self::ENABLED               => 'linking_enabled',
        self::ISSUER_CLASS          => 'linking_issuer_class',
        self::ORGANIZATION_CLAIM    => 'linking_organization_claim',
        self::ORGANIZATION_VALUE    => 'linking_organization_value',
        self::SAML_ATTRIBUTE        => 'linking_saml_attribute',
        self::SAML_ATTRIBUTE_FORMAT => 'linking_saml_attribute_format',
    ];

    /** @var list<string> The settings an acknowledgement stands for: changing one needs it given again. */
    private const array ACKNOWLEDGES = [self::ISSUER_CLASS, self::SAML_ATTRIBUTE, self::SAML_ATTRIBUTE_FORMAT];

    /** @var list<string> The settings a change may clear with `null`. */
    private const array CLEARABLE = [self::ISSUER_CLASS, self::ORGANIZATION_CLAIM, self::ORGANIZATION_VALUE, self::SAML_ATTRIBUTE, self::SAML_ATTRIBUTE_FORMAT];

    /** @var int The longest organisation claim, in bytes. */
    private const int MAX_CLAIM_LENGTH = 255;

    /** @var int The longest SAML attribute `Name`, in bytes. */
    private const int MAX_ATTRIBUTE_LENGTH = 1024;

    /** @var int The longest SAML attribute `NameFormat`, in bytes. */
    private const int MAX_FORMAT_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $finder
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Administration\AdministrationEvents  $events
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionSecrets  $secrets
     * @param  \SineMacula\Laravel\Sso\Linking\DomainLinkEligibility  $eligibility
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Links\LinkStorageBinding  $storage
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The tenant-scoped lookup, on the write connection. */
        private ConnectionFinder $finder,

        /** The freshness contract every change asks first. */
        private FreshnessGate $freshness,

        /** The reporter of every change. */
        private AdministrationEvents $events,

        /** The protocol drivers, for availability and the summary. */
        private ProtocolManager $protocols,

        /** The connections' encrypted secrets, masked in the summary. */
        private ConnectionSecrets $secrets,

        /** Knows which issuers are shared. */
        private DomainLinkEligibility $eligibility,

        /** The clock an acknowledgement is stamped from. */
        private Clock $clock,

        /** Whether the bound linker is backed by link storage. */
        private LinkStorageBinding $storage,
    ) {}

    /**
     * The tenant's connection's linking settings, as
     * `Contracts\SsoConnection::getLinkingSettings()` answers them, or `null`
     * when it has none.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return ?array<string, bool|int|string|null>
     *
     * @throws \InvalidArgumentException
     */
    public function get(string $tenantId, string $connectionId): ?array
    {
        return $this->finder->find($tenantId, $connectionId)?->getLinkingSettings();
    }

    /**
     * Change the tenant's connection's linking settings.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  array<array-key, mixed>  $changes
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function change(string $tenantId, string $connectionId, #[\SensitiveParameter] array $changes, ?ActingIdentity $actor = null): ConnectionResult
    {
        if ($this->finder->find($tenantId, $connectionId) === null) {
            return ConnectionResult::refused(FailureReason::CONNECTION_NOT_FOUND);
        }

        if (!$this->freshness->check(FreshnessOperation::CONNECTION_TRUST)->isFresh()) {
            return ConnectionResult::refused(FailureReason::FRESHNESS_REQUIRED);
        }

        return DB::connection(StorageConnection::name())->transaction(fn (): ConnectionResult => $this->changeLocked($tenantId, $connectionId, $changes, $actor));
    }

    /**
     * The code of what was given for the setting, or `null` when it is fine.
     *
     * @param  int|string  $name
     * @param  mixed  $value
     * @param  string  $protocol
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function codeOf(int|string $name, #[\SensitiveParameter] mixed $value, string $protocol): ?ViolationCode
    {
        if ($value === null && in_array($name, self::CLEARABLE, true)) {
            return null;
        }

        return match ($name) {
            self::ENABLED, self::ACKNOWLEDGED => SettingRules::boolean($value),
            self::ISSUER_CLASS                => SettingRules::choice($value, [DomainLinkEligibility::SHARED, DomainLinkEligibility::SINGLE_ORGANIZATION]),
            self::ORGANIZATION_CLAIM          => self::claimCode($value, $protocol),
            self::ORGANIZATION_VALUE          => SettingRules::text($value, LinkingEmail::MAX_ORGANIZATION_LENGTH),
            self::SAML_ATTRIBUTE              => self::samlCode($value, $protocol, self::MAX_ATTRIBUTE_LENGTH, true),
            self::SAML_ATTRIBUTE_FORMAT       => self::samlCode($value, $protocol, self::MAX_FORMAT_LENGTH, false),
            default                           => ViolationCode::UNKNOWN,
        };
    }

    /**
     * The code of an organisation claim: on SAML an attribute's `Name`, which
     * may hold whitespace; on OIDC a claim's name, which may not, and which is
     * never a protocol value, a token or the email.
     *
     * @param  mixed  $value
     * @param  string  $protocol
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function claimCode(mixed $value, string $protocol): ?ViolationCode
    {
        $code = SettingRules::text($value, self::MAX_CLAIM_LENGTH, $protocol === Saml2Driver::NAME);

        if ($code !== null || $protocol !== OidcDriver::NAME) {
            return $code;
        }

        return in_array($value, [...AttributeMapping::RESERVED_OIDC_SOURCES, 'email'], true) ? ViolationCode::RESERVED : null;
    }

    /**
     * The code of a SAML attribute's `Name` or `NameFormat`: `unsupported` on a
     * protocol that reads no SAML attribute.
     *
     * @param  mixed  $value
     * @param  string  $protocol
     * @param  int  $maxBytes
     * @param  bool  $whitespace
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function samlCode(mixed $value, string $protocol, int $maxBytes, bool $whitespace): ?ViolationCode
    {
        return $protocol === Saml2Driver::NAME ? SettingRules::text($value, $maxBytes, $whitespace) : ViolationCode::UNSUPPORTED;
    }

    /**
     * The settings as the change leaves them, with whether the acknowledgement
     * still stands: given as `true`, or not given and nothing it stands for
     * changed.
     *
     * @param  array<string, bool|int|string|null>  $current
     * @param  array<array-key, mixed>  $changes
     * @return array<string, mixed>
     */
    private static function merged(array $current, #[\SensitiveParameter] array $changes): array
    {
        $merged = array_replace($current, $changes);

        if (!array_key_exists(self::ACKNOWLEDGED, $changes)) {
            $merged[self::ACKNOWLEDGED] = $current[self::ACKNOWLEDGED] === true && !self::isAcknowledgementStale($current, $merged);
        }

        return $merged;
    }

    /**
     * Whether something the acknowledgement stands for changed.
     *
     * @param  array<string, bool|int|string|null>  $current
     * @param  array<string, mixed>  $merged
     * @return bool
     */
    private static function isAcknowledgementStale(array $current, #[\SensitiveParameter] array $merged): bool
    {
        foreach (self::ACKNOWLEDGES as $name) {

            if ($merged[$name] !== $current[$name]) {
                return true;
            }
        }

        return false;
    }

    /**
     * What the classification requires, whether shared or not: an issuer the
     * package knows to be shared can be nothing else.
     *
     * @param  array<string, mixed>  $merged
     * @param  ?string  $required
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function classification(#[\SensitiveParameter] array $merged, ?string $required): array
    {
        $class = $merged[self::ISSUER_CLASS];

        $code = match (true) {
            $class === null                                                => ViolationCode::REQUIRED,
            $required !== null && $class !== DomainLinkEligibility::SHARED => ViolationCode::NOT_ALLOWED,
            default                                                        => null,
        };

        $isShared = $required !== null || $class === DomainLinkEligibility::SHARED;

        return [...SettingRules::at(self::ISSUER_CLASS, $code), ...($isShared ? self::organization($merged, $required) : [])];
    }

    /**
     * What a shared issuer requires: the claim, the very one the package knows
     * when it knows the issuer, and the value.
     *
     * @param  array<string, mixed>  $merged
     * @param  ?string  $required
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function organization(#[\SensitiveParameter] array $merged, ?string $required): array
    {
        $claim = $merged[self::ORGANIZATION_CLAIM];

        $code = match (true) {
            $claim === null                            => ViolationCode::REQUIRED,
            $required !== null && $claim !== $required => ViolationCode::NOT_ALLOWED,
            default                                    => null,
        };

        return [
            ...SettingRules::at(self::ORGANIZATION_CLAIM, $code),
            ...SettingRules::at(self::ORGANIZATION_VALUE, $merged[self::ORGANIZATION_VALUE] === null ? ViolationCode::REQUIRED : null),
        ];
    }

    /**
     * What a SAML connection requires: the attribute's `Name` and `NameFormat`.
     *
     * @param  array<string, mixed>  $merged
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function samlAttribute(#[\SensitiveParameter] array $merged): array
    {
        return [
            ...SettingRules::at(self::SAML_ATTRIBUTE, $merged[self::SAML_ATTRIBUTE] === null ? ViolationCode::REQUIRED : null),
            ...SettingRules::at(self::SAML_ATTRIBUTE_FORMAT, $merged[self::SAML_ATTRIBUTE_FORMAT] === null ? ViolationCode::REQUIRED : null),
        ];
    }

    /**
     * The names, for the event and the result, of the settings the change
     * changes.
     *
     * @param  array<string, bool|int|string|null>  $current
     * @param  array<string, mixed>  $merged
     * @return list<string>
     */
    private static function changedNames(array $current, #[\SensitiveParameter] array $merged): array
    {
        $names = [];

        foreach ([...array_keys(self::COLUMNS), self::ACKNOWLEDGED] as $name) {

            if ($merged[$name] === $current[$name]) {
                continue;
            }

            $names[] = self::CHANGED_PREFIX . $name;
        }

        return $names;
    }

    /**
     * Under the connection's lock: refuse what no longer stands or is invalid,
     * and write what changes.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  array<array-key, mixed>  $changes
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    private function changeLocked(string $tenantId, string $connectionId, #[\SensitiveParameter] array $changes, ?ActingIdentity $actor): ConnectionResult
    {
        $locked = $this->finder->findForUpdate($tenantId, $connectionId);

        if ($locked === null || !$this->protocols->isAvailable($locked->protocol)) {
            return ConnectionResult::refused($locked === null ? FailureReason::CONNECTION_NOT_FOUND : FailureReason::PROTOCOL_UNAVAILABLE);
        }

        $current    = $locked->getLinkingSettings();
        $violations = self::given($changes, $locked->protocol);
        $merged     = self::merged($current, $changes);

        if ($violations === [] && $merged[self::ENABLED] === true) {
            $violations = $this->requirements($locked, $merged);
        }

        return $violations === [] ? $this->written($locked, $current, $merged, $actor) : ConnectionResult::invalid($violations);
    }

    /**
     * Every violation in what was given, each setting judged alone.
     *
     * @param  array<array-key, mixed>  $changes
     * @param  string  $protocol
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function given(#[\SensitiveParameter] array $changes, string $protocol): array
    {
        $violations = [];

        foreach ($changes as $name => $value) {
            array_push($violations, ...SettingRules::at(SettingRules::path(null, $name), self::codeOf($name, $value, $protocol)));
        }

        return $violations;
    }

    /**
     * Every violation of linking being on with the merged settings: the
     * feature, the classification, the acknowledgement and the SAML attribute.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, mixed>  $merged
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     *
     * @throws \LogicException
     */
    private function requirements(Connection $locked, #[\SensitiveParameter] array $merged): array
    {
        $this->storage->require('Linking by a verified domain');

        $isSaml   = $locked->protocol === Saml2Driver::NAME;
        $issuer   = $locked->settings['issuer'] ?? $locked->settings['idp_entity_id'] ?? null;
        $required = is_string($issuer) ? $this->eligibility->requiredClaim($locked->protocol, $issuer) : null;
        $needsAck = $isSaml || ($required === null && $merged[self::ISSUER_CLASS] === DomainLinkEligibility::SINGLE_ORGANIZATION);

        return [
            ...SettingRules::at(self::ENABLED, Features::enabled(Feature::DOMAIN_LINKING) ? null : ViolationCode::UNSUPPORTED),
            ...self::classification($merged, $required),
            ...($isSaml ? self::samlAttribute($merged) : []),
            ...SettingRules::at(self::ACKNOWLEDGED, $needsAck && $merged[self::ACKNOWLEDGED] !== true ? ViolationCode::REQUIRED : null),
        ];
    }

    /**
     * Write what the change changes, raise the linking version, delete the open
     * reservations and report it, or answer `unchanged`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, bool|int|string|null>  $current
     * @param  array<string, mixed>  $merged
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    private function written(Connection $locked, array $current, #[\SensitiveParameter] array $merged, ?ActingIdentity $actor): ConnectionResult
    {
        $names = self::changedNames($current, $merged);

        if ($names === []) {
            return ConnectionResult::unchanged($this->summary($locked));
        }

        $columns = [];

        foreach (self::COLUMNS as $name => $column) {
            $columns[$column] = $merged[$name];
        }

        $locked->forceFill([
            ...$columns,
            'linking_acknowledged_at' => $this->acknowledgedAt($locked, $current, $merged),
            'linking_version'         => $locked->linking_version + 1,
        ])->save();

        ReservationWithdrawal::ofConnection($locked);

        $this->events->connectionUpdated($locked, $names, $actor);

        return ConnectionResult::updated($this->summary($locked), $names);
    }

    /**
     * When the acknowledgement that stands was given: kept when it stands for
     * what it was given about, and now when it was given again for something
     * else; `null` when none stands.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, bool|int|string|null>  $current
     * @param  array<string, mixed>  $merged
     * @return ?\Carbon\CarbonImmutable
     */
    private function acknowledgedAt(Connection $locked, array $current, #[\SensitiveParameter] array $merged): ?CarbonImmutable
    {
        if ($merged[self::ACKNOWLEDGED] !== true) {
            return null;
        }

        return self::isAcknowledgementStale($current, $merged) ? $this->clock->now() : ($locked->linking_acknowledged_at ?? $this->clock->now());
    }

    /**
     * The summary of the connection.
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
}
