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
 * Locks a tenant's enforcement row, the first lock in the package's lock order.
 *
 * Call inside the caller's transaction on the storage connection.
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
     * The tenant's row locked for update, inserted unconfigured if missing.
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
     * Whether the row holds a rule; every change writes a version.
     *
     * @param  \SineMacula\Laravel\Sso\Models\TenantEnforcement  $enforcement
     * @return bool
     */
    public static function isConfigured(TenantEnforcement $enforcement): bool
    {
        return $enforcement->version !== null;
    }

    /**
     * Without a transaction the lock would end with its statement.
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
     * Fail when the row the upsert made sure of cannot be read.
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
     * Insert an unconfigured row unless one exists; racing locking reads of a
     * missing row would deadlock on MySQL gap locks.
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
