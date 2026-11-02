<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use SineMacula\Laravel\Sso\Enforcement\LockedEnforcement;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The locks a redemption holds before it locks its code (SSO-4.6, SSO-8.5,
 * decision D5), as `HandoffRecheck::lock()` took them for a tenant, a
 * connection and an application: under the package's default enforcement
 * contract with the `enforcement` feature on, the enforcing tenant's rule and
 * then the connection and the rule's connections, in id order; otherwise the
 * connection alone; then, for a handoff bound to a reservation, its domain
 * claim. `HandoffRecheck::recheck()` and `acknowledgeSignIn()` take one, so
 * neither is reached without the locks taken first, in the package's lock
 * order.
 *
 * It holds the connection's row as locked (`null` when it is gone, or of
 * another tenant) and the locked enforcement, and lives only for the
 * transaction it was taken in: the locks end with it, and a lock kept for
 * another transaction protects nothing. Only `HandoffRecheck::lock()` makes
 * one.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecheckLock
{
    /**
     * Constructor.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $application
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\LockedEnforcement  $enforcement
     * @param  ?\SineMacula\Laravel\Sso\Models\Domain  $domain
     */
    private function __construct(

        /** The tenant the locks were taken for. */
        public string $tenantId,

        /** The connection the locks were taken for. */
        public string $connectionId,

        /** The application the locks were taken for. */
        public string $application,

        /** The connection's row, locked, or `null` when it is gone or of another tenant. */
        public ?Connection $connection,

        /** The enforcing tenant's rule and its connections, locked, when the default contract applies. */
        public ?LockedEnforcement $enforcement,

        /** The domain claim a reservation is bound to, locked, or `null` when there is none. */
        public ?Domain $domain = null,
    ) {}

    /**
     * The locks as taken. Only `HandoffRecheck::lock()` calls it.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $application
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\LockedEnforcement  $enforcement
     * @param  ?\SineMacula\Laravel\Sso\Models\Domain  $domain
     * @return self
     *
     * @internal
     */
    public static function held(string $tenantId, string $connectionId, string $application, ?Connection $connection, ?LockedEnforcement $enforcement, ?Domain $domain = null): self
    {
        return new self($tenantId, $connectionId, $application, $connection, $enforcement, $domain);
    }

    /**
     * Whether the locks were taken for the result's tenant, connection and
     * application, compared exactly.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return bool
     */
    public function isFor(VerifiedResult $result): bool
    {
        return [$this->tenantId, $this->connectionId, $this->application] === [$result->tenantId, $result->connectionId, $result->application];
    }
}
