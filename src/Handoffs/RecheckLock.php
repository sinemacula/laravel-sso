<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use SineMacula\Laravel\Sso\Enforcement\LockedEnforcement;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The locks a redemption holds before it locks its code (SSO-4.6, SSO-8.5,
 * decision D5), as `HandoffRecheck::lock()` took them for a tenant, a
 * connection and an application: for a handoff bound to a reservation or a
 * `link`, its identity's guard; under the package's default enforcement
 * contract with the `enforcement` feature on, the enforcing tenant's rule and
 * then the connection and the rule's connections, in id order; otherwise the
 * connection alone; for a `link`, with those the connections holding the
 * identity's verified domain links, and whether the identity has ever held one,
 * as its guard records; then, for a handoff bound to a reservation, its domain
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
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $guarded
     * @param  list<string>  $lockedConnectionIds
     * @param  bool  $domainLinkHeld
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

        /** The identity whose guard is held, or `null` when none was taken. */
        public ?IdentityReference $guarded = null,

        /** The ids of every connection locked. */
        public array $lockedConnectionIds = [],

        /** Whether the guarded identity of a `link` has ever held an active link by a verified domain. */
        public bool $domainLinkHeld = false,
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
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $guarded
     * @param  list<string>  $lockedConnectionIds
     * @param  bool  $domainLinkHeld
     * @return self
     *
     * @internal
     *
     * @SuppressWarnings("php:S107")
     */
    public static function held(
        string $tenantId,
        string $connectionId,
        string $application,
        ?Connection $connection,
        ?LockedEnforcement $enforcement,
        ?Domain $domain = null,
        ?IdentityReference $guarded = null,
        array $lockedConnectionIds = [],
        bool $domainLinkHeld = false,
    ): self {
        return new self($tenantId, $connectionId, $application, $connection, $enforcement, $domain, $guarded, $lockedConnectionIds, $domainLinkHeld);
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

    /**
     * Whether the identity's guard is held, compared byte for byte.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     */
    public function isGuarding(IdentityReference $identity): bool
    {
        return $this->guarded?->is($identity) ?? false;
    }

    /**
     * Whether the connection's row is among those locked.
     *
     * @param  string  $connectionId
     * @return bool
     */
    public function covers(string $connectionId): bool
    {
        return in_array($connectionId, $this->lockedConnectionIds, true);
    }
}
