<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;

/**
 * The lock on a tenant's enforcement row (SSO-4.5, SSO-4.6): the first lock of
 * the package's order, which every change to the rule and every admission it
 * judges (a redemption's recheck, a completion's enforcement step) takes first,
 * so a session is never admitted against a rule that is changing.
 *
 * `acquire()` runs, on the storage connection, inside the transaction the
 * caller has open there, an insert of an unconfigured row for the tenant unless
 * it has one, keyed by `tenant_hash`, which leaves an existing row's values
 * exactly as they are; and then a locking read of the row. A tenant that never
 * had a rule thus still has a row to lock, and racing first lockers queue on
 * it: a locking read of a row that does not exist would take a gap lock on
 * MySQL, and racers would deadlock on each other's gap locks, while the upsert
 * locks the row exclusively at once (`ON DUPLICATE KEY UPDATE`, `ON CONFLICT
 * ... DO UPDATE`). Both statements are current reads, so a caller's older
 * `REPEATABLE READ` snapshot never answers. On PostgreSQL under `REPEATABLE
 * READ`, a locker that waited on a change may instead fail to serialise: that
 * error propagates, and the caller retries its whole transaction.
 *
 * The unconfigured row (no version, no `changed_at`, off, with no connection)
 * reads everywhere exactly as no row: `EnforcementFinder::find()` answers none
 * for it, the policy carries no version, and its first change reports no
 * previous version. It is never deleted, since another transaction may be
 * waiting to lock it.
 *
 * Called with no transaction open on the storage connection it is a
 * `LogicException`, since the lock would end with the statement. An empty or
 * overlong tenant id is an `InvalidArgumentException`; a database error
 * propagates (SSO-11.4). It holds the finder and the clock, neither of which
 * keeps anything of one call for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnforcementLock
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementFinder  $finder
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Reads the row back, locked. */
        private EnforcementFinder $finder,

        /** The clock an inserted row is stamped from. */
        private Clock $clock,
    ) {}

    /**
     * The tenant's row, configured or not, locked for update until the caller's
     * transaction ends; inserted unconfigured first when the tenant has none.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Models\TenantEnforcement
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    public function acquire(string $tenantId): TenantEnforcement
    {
        EnforcementFinder::assertTenant($tenantId);
        self::assertInTransaction();

        $this->insertUnlessExists($tenantId);

        return $this->finder->row($tenantId, true) ?? self::unreadable();
    }

    /**
     * Whether the row holds a rule: one with a version, which every change
     * writes. An unconfigured row is the same as none.
     *
     * @param  \SineMacula\Laravel\Sso\Models\TenantEnforcement  $enforcement
     * @return bool
     */
    public static function isConfigured(TenantEnforcement $enforcement): bool
    {
        return $enforcement->version !== null;
    }

    /**
     * Refuse to lock with no transaction open on the storage connection, where
     * the lock would end with its statement.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertInTransaction(): void
    {
        if (DB::connection(StorageConnection::name())->transactionLevel() > 0) {
            return;
        }

        throw new \LogicException('A tenant\'s enforcement is locked inside a transaction on the package\'s storage connection.');
    }

    /**
     * Refuse to go on without the row the upsert has just made sure of.
     *
     * @return never
     *
     * @throws \UnexpectedValueException
     */
    private static function unreadable(): never
    {
        throw new \UnexpectedValueException('The tenant\'s enforcement could not be read back.');
    }

    /**
     * Insert the tenant's row unconfigured (off, with no connection, no version
     * and no time of change), unless the tenant has one: then the row is left
     * as it is, and locked.
     *
     * @param  string  $tenantId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function insertUnlessExists(string $tenantId): void
    {
        $enforcement = new TenantEnforcement;
        $now         = UtcDateTime::format($enforcement, $this->clock->now());

        $enforcement->newQuery()->upsert([
            'id'             => strtolower((string) Str::ulid()),
            'tenant_id'      => $tenantId,
            'tenant_hash'    => TenantHash::of($tenantId),
            'enabled'        => false,
            'connection_ids' => '[]',
            'version'        => null,
            'changed_at'     => null,
            'created_at'     => $now,
            'updated_at'     => $now,
        ], ['tenant_hash'], ['tenant_hash']);
    }
}
