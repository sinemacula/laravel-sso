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
 * The management helper of a tenant's enforcement (SSO-4.1, SSO-4.3, SSO-4.5,
 * SSO-2.11, SSO-2.12): read it, and turn it on or off or change which of the
 * tenant's connections satisfy it, for the application's own administration
 * screens; who may call it is the application's authorisation, never the
 * package's.
 *
 * A change goes in one order, and a refusal at any step writes, revokes and
 * reports nothing:
 *
 * 1. While the `enforcement` feature is off it is `feature_disabled`.
 * 2. The connection ids are validated as a whole: each a string of 1 to 26
 *    bytes (`connection_ids.<n>`, `invalid_type` or `invalid_format`),
 *    de-duplicated silently, at most `MAX_CONNECTIONS` (`too_many`), at least
 *    one while turning it on (`required`), and each a connection of this tenant
 *    (`unknown`, the same for another tenant's connection as for none, so no
 *    other tenant is revealed). A violation is `invalid`.
 * 3. A change to what is stored already (the same switch and the same set of
 *    ids, in any order) is `unchanged`, with nothing asked.
 * 4. Turning it on needs one of the connections given to be enabled and to have
 *    completed a sign-in, so a misconfigured connection cannot lock the tenant
 *    out (SSO-4.3): otherwise `completed_sign_in_required`.
 * 5. The freshness contract is asked with `sso.enforcement.update` and its
 *    maximum age: `stale` is `freshness_required`.
 * 6. In one transaction on the storage connection, the tenant's row is locked
 *    (through `EnforcementLock`, which inserts it unconfigured first when there
 *    is none), then the connections given are locked in id order, the lock
 *    order every caller keeps; steps 2 to 4 are judged again on the locked
 *    rows, an unconfigured row counting as no rule; the row is written with a
 *    new version, a fresh lower-case ULID; when the rule is now on,
 *    `Contracts\SessionRevocation`, resolved from the container at that moment,
 *    is called with the tenant's policy as it now is
 *    (`RevocationScope::tenant()`); and the change is reported through
 *    `Administration\EnforcementEvents`, after commit.
 *
 * Turning it off revokes nothing. The revocation runs inside the transaction,
 * so an adapter that writes through the same Laravel connection commits or
 * rolls back with the change; an exception it throws rolls the whole change
 * back, with no row, no new version and no event, and propagates. A row is
 * never found by a plain read under the lock: each read that decides the write
 * is a locking read, so a caller's own `REPEATABLE READ` snapshot cannot hide a
 * concurrent change. A tenant's first row is inserted unconfigured by an upsert
 * that leaves an existing row as it is, so racing first changes queue on the
 * row rather than on MySQL's gap locks; an unconfigured row reads as no rule,
 * so one a refused change leaves behind stores nothing, and it is kept, since a
 * redemption or a completion may be waiting to lock it. The revocation, inside
 * the change's transaction, uses current reads and writes, so it sees every
 * session an admission that held the lock first committed. A deadlock is
 * retried, up to `ATTEMPTS` times, when the helper's transaction is the
 * outermost one; inside the application's own, it propagates, as does
 * PostgreSQL's serialisation failure, for the caller to retry its whole
 * transaction.
 *
 * A database error propagates (SSO-11.4); an empty or overlong tenant id is an
 * `InvalidArgumentException`. It holds the lookups, the freshness gate, the
 * clock, the reporter and the container, none of which keeps anything of one
 * request for the next (SSO-11.2). Resolve it from the container per request.
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

    /** @var int How many times a transaction a deadlock rolled back is tried in all. */
    private const int ATTEMPTS = 3;

    /** @var int The longest connection id, a ULID. */
    private const int MAX_ID_LENGTH = 26;

    /** @var string The connection ids, as a violation names them. */
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

        /** Reports each change, inside its transaction. */
        private EnforcementEvents $events,

        /** Resolves the revocation contract at each change. */
        private Container $container,
    ) {}

    /**
     * The tenant's enforcement as it is stored: off, with no connection and no
     * version, when it never had one.
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

        // A rule that looks unchanged asks no freshness, but is answered only
        // once the locked read agrees: the first read may come from a caller's
        // transaction's snapshot, older than a change committed since.
        $unchanged = $refusal?->status === EnforcementStatus::UNCHANGED;
        $refusal   = $unchanged ? null : ($refusal ?? $this->staleRefusal($caller));

        return $refusal ?? $this->change($tenantId, $stored !== null, $enabled, $ids, $caller, $client, !$unchanged);
    }

    /**
     * The valid ids given, each once, by the position it was first given at;
     * every violation, in the order given, a violation of the whole list
     * first; and the tenant's connections among the ids, found one by one
     * through the tenant-scoped lookup, unless there are too many to look up.
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
     * The tenant's connections with the ids, found one by one through the
     * tenant-scoped lookup on the write connection.
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
     * The refusal of a caller whose authentication is not fresh enough to
     * change enforcement, or `null` when it is.
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
     * Make the change in one transaction on the storage connection, against the
     * tenant's row and the connections given, each locked and judged again;
     * retried when a deadlock rolled back the outermost transaction. A caller
     * whose freshness was not asked, because the rule looked unchanged, is
     * asked once the locked read finds a change to make.
     *
     * @param  string  $tenantId
     * @param  bool  $exists
     * @param  bool  $enabled
     * @param  array<int, string>  $ids
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  bool  $freshnessAsked
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function change(string $tenantId, bool $exists, bool $enabled, array $ids, ?Caller $caller, ClientContext $client, bool $freshnessAsked): EnforcementResult
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($tenantId, $exists, $enabled, $ids, $caller, $client, $freshnessAsked): EnforcementResult {

            $locked      = $this->locked($tenantId, $exists);
            $stored      = EnforcementLock::isConfigured($locked) ? $locked : null;
            $connections = $this->finder->connections($tenantId, array_values($ids), true);
            $unknown     = self::unknown($ids, $connections);

            $refusal = $unknown === []
                ? self::ruleRefusal($tenantId, $stored, $enabled, $ids, $connections)
                : EnforcementResult::invalid(array_values($unknown));

            $refusal ??= $freshnessAsked ? null : $this->staleRefusal($caller);

            return $refusal ?? $this->write($locked, $stored?->version, $enabled, $ids, $connections, $caller, $client);
        }, self::ATTEMPTS);
    }

    /**
     * The tenant's row, configured or not, locked for update. One the first
     * read saw configured is locked by a locking read; otherwise, or when that
     * finds none, the lock inserts it unconfigured unless one exists, and reads
     * it locked.
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
     * Write the change to the locked row with a new version, revoke the
     * sessions the rule, when on, no longer allows, and report the change.
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
        $locked->forceFill([
            'enabled'        => $enabled,
            'connection_ids' => EnforcementSummary::sorted($ids),
            'version'        => self::ulid(),
            'changed_at'     => $this->clock->now(),
        ])->save();

        if ($enabled) {

            $policy = EnforcementPolicy::required($locked->tenant_id, $locked->tenant_id, EnforcementFinder::enabledIds($connections), $locked->version);

            $this->container->make(SessionRevocation::class)->revoke(RevocationScope::tenant($policy));
        }

        $this->events->changed($locked, $previousVersion, $caller, $client);

        return EnforcementResult::updated(EnforcementSummary::of($locked->tenant_id, $locked));
    }

    /**
     * The ids given that could be connection ids, each once, by the position it
     * was first given at, and a violation, by position, for each that could
     * not.
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
     * Whether the string is as long as a connection's id may be: 1 to 26 bytes.
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
     * The violation of a value at the position that cannot be a connection's
     * id: `invalid_format` for a string of the wrong length, `invalid_type` for
     * anything else.
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
     * An `unknown` violation, by position, for each id that is none of the
     * connections found, compared byte for byte.
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
     * Why the change is not made, judged against the stored row and the
     * connections given: `unchanged` when it would store what is stored, and
     * `completed_sign_in_required` when it turns the rule on without an enabled
     * connection that has completed a sign-in; `null` otherwise.
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
     * Whether the stored rule is already the one given: the same switch and the
     * same set of ids, in whatever order.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementSummary  $stored
     * @param  bool  $enabled
     * @param  array<int, string>  $ids
     * @return bool
     */
    private static function isSame(EnforcementSummary $stored, bool $enabled, array $ids): bool
    {
        return $stored->enabled === $enabled && $stored->connectionIds === EnforcementSummary::sorted($ids);
    }

    /**
     * A new lower-case ULID.
     *
     * @return string
     */
    private static function ulid(): string
    {
        return strtolower((string) Str::ulid());
    }
}
