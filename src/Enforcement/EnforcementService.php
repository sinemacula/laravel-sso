<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\Sso\Administration\EnforcementEvents;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\RetriedTransaction;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\Enums\EnforcementStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * Reads and changes a tenant's enforcement; a refused change writes, revokes
 * and reports nothing. Authorising the caller is the application's job.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnforcementService
{
    /** @var int The most connections that may satisfy one tenant's enforcement. */
    public const int MAX_CONNECTIONS = 50;

    /** @var int Total tries of a transaction a deadlock rolled back. */
    private const int ATTEMPTS = 3;

    /** @var int The longest connection id, a ULID. */
    private const int MAX_ID_LENGTH = 26;

    /** @var string The setting a violation names. */
    private const string CONNECTION_IDS = 'connection_ids';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $connections
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementFinder  $finder
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementLock  $lock
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Administration\EnforcementEvents  $events
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Finds the tenant's connections, on the write connection. */
        private ConnectionFinder $connections,

        /** Finds the enforcement, and locks its connections. */
        private EnforcementFinder $finder,

        /** Locks the tenant's row, inserting it unconfigured when it has none. */
        private EnforcementLock $lock,

        /** Asks the freshness contract before a change is written. */
        private FreshnessGate $freshness,

        /** The clock every change is stamped from. */
        private Clock $clock,

        /** Reports each change. */
        private EnforcementEvents $events,

        /** Resolves the revocation contract at each change. */
        private Container $container,
    ) {}

    /**
     * The tenant's enforcement as stored, off when it never had one.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementSummary
     *
     * @throws \InvalidArgumentException
     */
    public function get(string $tenantId): EnforcementSummary
    {
        return EnforcementSummary::of($tenantId, $this->finder->find($tenantId));
    }

    /**
     * Turn the tenant's enforcement on or off, satisfied by the tenant's
     * connections with the ids given.
     *
     * @param  string  $tenantId
     * @param  bool  $enabled
     * @param  array<array-key, mixed>  $connectionIds
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function update(string $tenantId, bool $enabled, array $connectionIds, ClientContext $client, ?Caller $caller = null): EnforcementResult
    {
        EnforcementFinder::assertTenant($tenantId);

        if (!Features::enabled(Feature::ENFORCEMENT)) {
            return EnforcementResult::refused(FailureReason::FEATURE_DISABLED);
        }

        [$ids, $violations, $connections] = $this->validated($tenantId, $enabled, $connectionIds);

        $stored  = $violations === [] ? $this->finder->find($tenantId) : null;
        $refusal = $violations === []
            ? self::ruleRefusal($tenantId, $stored, $enabled, $ids, $connections)
            : EnforcementResult::invalid($violations);

        // An apparently unchanged rule is confirmed under the lock, since the
        // first read may come from the caller's stale transaction snapshot
        if ($refusal !== null && $refusal->status !== EnforcementStatus::UNCHANGED) {
            return $refusal;
        }

        return $this->change($tenantId, $stored !== null, $enabled, $ids, $caller, $client);
    }

    /**
     * The valid ids by first position, every violation in order, and the
     * tenant's connections among the ids.
     *
     * @param  string  $tenantId
     * @param  bool  $enabled
     * @param  array<array-key, mixed>  $given
     * @return array{0: array<int, string>, 1: list<\SineMacula\Laravel\Sso\Connections\SettingViolation>, 2: list<\SineMacula\Laravel\Sso\Models\Connection>}
     *
     * @throws \InvalidArgumentException
     */
    private function validated(string $tenantId, bool $enabled, array $given): array
    {
        [$ids, $violations] = self::parsed(array_values($given));

        $tooMany = count($ids) > self::MAX_CONNECTIONS;

        $code = match (true) {
            $tooMany                  => ViolationCode::TOO_MANY,
            $enabled && $given === [] => ViolationCode::REQUIRED,
            default                   => null,
        };

        $connections = $tooMany ? [] : $this->found($tenantId, $ids);

        $violations += $code === null ? [] : [-1 => new SettingViolation(self::CONNECTION_IDS, $code)];
        $violations += $tooMany ? [] : self::unknown($ids, $connections);

        ksort($violations);

        return [$ids, array_values($violations), $connections];
    }

    /**
     * The tenant's connections with the ids, through the tenant-scoped lookup.
     *
     * @param  string  $tenantId
     * @param  array<int, string>  $ids
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     *
     * @throws \InvalidArgumentException
     */
    private function found(string $tenantId, array $ids): array
    {
        $found = array_map(fn (string $id): ?Connection => $this->connections->find($tenantId, $id), array_values($ids));

        return array_values(array_filter($found, static fn (?Connection $connection): bool => $connection !== null));
    }

    /**
     * The refusal of a caller whose authentication is stale, `null` when fresh.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return ?\SineMacula\Laravel\Sso\Enforcement\EnforcementResult
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function staleRefusal(?Caller $caller): ?EnforcementResult
    {
        return $this->freshness->check(FreshnessOperation::ENFORCEMENT_UPDATE, $caller)->isFresh()
            ? null
            : EnforcementResult::refused(FailureReason::FRESHNESS_REQUIRED);
    }

    /**
     * Lock, judge again, ask freshness and write the change in one retried
     * transaction.
     *
     * @param  string  $tenantId
     * @param  bool  $exists
     * @param  bool  $enabled
     * @param  array<int, string>  $ids
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function change(string $tenantId, bool $exists, bool $enabled, array $ids, ?Caller $caller, ClientContext $client): EnforcementResult
    {
        $connection = DB::connection(StorageConnection::name());

        return RetriedTransaction::run($connection, function () use ($tenantId, $exists, $enabled, $ids, $caller, $client): EnforcementResult {

            $locked      = $this->locked($tenantId, $exists);
            $stored      = EnforcementLock::isConfigured($locked) ? $locked : null;
            $connections = $this->finder->connections($tenantId, array_values($ids), true);
            $unknown     = self::unknown($ids, $connections);

            $refusal = $unknown === []
                ? self::ruleRefusal($tenantId, $stored, $enabled, $ids, $connections)
                : EnforcementResult::invalid(array_values($unknown));

            $refusal ??= $this->staleRefusal($caller);

            return $refusal ?? $this->write($locked, $stored?->version, $enabled, $ids, $connections, $caller, $client);
        }, self::ATTEMPTS);
    }

    /**
     * The tenant's row locked for update, inserted unconfigured if missing.
     *
     * @param  string  $tenantId
     * @param  bool  $exists
     * @return \SineMacula\Laravel\Sso\Models\TenantEnforcement
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    private function locked(string $tenantId, bool $exists): TenantEnforcement
    {
        $locked = $exists ? $this->finder->row($tenantId, true) : null;

        return $locked ?? $this->lock->acquire($tenantId);
    }

    /**
     * Write a new version, revoke what an enabled rule disallows, and report.
     *
     * @param  \SineMacula\Laravel\Sso\Models\TenantEnforcement  $locked
     * @param  ?string  $previousVersion
     * @param  bool  $enabled
     * @param  array<int, string>  $ids
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $connections
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementResult
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function write(
        TenantEnforcement $locked,
        ?string $previousVersion,
        bool $enabled,
        array $ids,
        array $connections,
        ?Caller $caller,
        ClientContext $client,
    ): EnforcementResult {
        $version = self::ulid();

        $locked->forceFill([
            'enabled'        => $enabled,
            'connection_ids' => EnforcementSummary::sorted($ids),
            'version'        => $version,
            'changed_at'     => $this->clock->now(),
        ])->save();

        if ($enabled) {

            $policy = EnforcementPolicy::required($locked->tenant_id, $locked->tenant_id, EnforcementFinder::enabledIds($connections), $version);

            $this->container->make(SessionRevocation::class)->revoke(RevocationScope::tenant($policy));
        }

        $this->events->changed($locked, $version, $previousVersion, $caller, $client);

        return EnforcementResult::updated(EnforcementSummary::of($locked->tenant_id, $locked));
    }

    /**
     * Well-formed ids, deduplicated, and a violation per malformed one, keyed
     * by position.
     *
     * @param  list<mixed>  $given
     * @return array{0: array<int, string>, 1: array<int, \SineMacula\Laravel\Sso\Connections\SettingViolation>}
     */
    private static function parsed(array $given): array
    {
        $ids        = [];
        $violations = [];
        $seen       = [];

        foreach ($given as $position => $id) {

            if (!is_string($id) || !self::fitsId($id)) {
                $violations[$position] = self::malformed($position, $id);
                continue;
            }

            if (isset($seen[$id])) {
                continue;
            }

            $seen[$id]      = true;
            $ids[$position] = $id;
        }

        return [$ids, $violations];
    }

    /**
     * Whether the string is 1 to 26 bytes, as a connection id may be.
     *
     * @param  string  $value
     * @return bool
     */
    private static function fitsId(string $value): bool
    {
        $length = strlen($value);

        return $length > 0 && $length <= self::MAX_ID_LENGTH;
    }

    /**
     * `invalid_format` for a string of the wrong length, else `invalid_type`.
     *
     * @param  int  $position
     * @param  mixed  $value
     * @return \SineMacula\Laravel\Sso\Connections\SettingViolation
     */
    private static function malformed(int $position, mixed $value): SettingViolation
    {
        return new SettingViolation(self::CONNECTION_IDS . '.' . $position, is_string($value) ? ViolationCode::INVALID_FORMAT : ViolationCode::INVALID_TYPE);
    }

    /**
     * An `unknown` violation, by position, for each id not found.
     *
     * @param  array<int, string>  $ids
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $connections
     * @return array<int, \SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function unknown(array $ids, array $connections): array
    {
        $found      = array_map(static fn (Connection $connection): string => $connection->id, $connections);
        $violations = [];

        foreach ($ids as $position => $id) {

            if (in_array($id, $found, true)) {
                continue;
            }

            $violations[$position] = new SettingViolation(self::CONNECTION_IDS . '.' . $position, ViolationCode::UNKNOWN);
        }

        return $violations;
    }

    /**
     * `unchanged`, `completed_sign_in_required` (so a misconfigured connection
     * cannot lock the tenant out), or `null` when the change may go ahead.
     *
     * @param  string  $tenantId
     * @param  ?\SineMacula\Laravel\Sso\Models\TenantEnforcement  $stored
     * @param  bool  $enabled
     * @param  array<int, string>  $ids
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $connections
     * @return ?\SineMacula\Laravel\Sso\Enforcement\EnforcementResult
     *
     * @throws \InvalidArgumentException
     */
    private static function ruleRefusal(string $tenantId, ?TenantEnforcement $stored, bool $enabled, array $ids, array $connections): ?EnforcementResult
    {
        $summary   = EnforcementSummary::of($tenantId, $stored);
        $completed = array_filter($connections, static fn (Connection $connection): bool => $connection->enabled && $connection->has_completed_sign_in);

        return match (true) {
            self::isSame($summary, $enabled, $ids) => EnforcementResult::unchanged($summary),
            $enabled && $completed === []          => EnforcementResult::refused(FailureReason::COMPLETED_SIGN_IN_REQUIRED),
            default                                => null,
        };
    }

    /**
     * Whether a rule is stored with the same switch and set of ids; a tenant
     * with none stores its first, an off rule included, since it stops one an
     * inheritance would apply.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementSummary  $stored
     * @param  bool  $enabled
     * @param  array<int, string>  $ids
     * @return bool
     */
    private static function isSame(EnforcementSummary $stored, bool $enabled, array $ids): bool
    {
        return $stored->version !== null && $stored->enabled === $enabled && $stored->connectionIds === EnforcementSummary::sorted($ids);
    }

    /**
     * Lower-case ULID.
     *
     * @return string
     */
    private static function ulid(): string
    {
        return strtolower((string) Str::ulid());
    }
}
