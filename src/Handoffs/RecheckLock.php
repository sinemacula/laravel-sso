<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use SineMacula\Laravel\Sso\Enforcement\LockedEnforcement;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The locks a redemption holds before it locks its code.
 *
 * Valid only in the transaction `HandoffRecheck::lock()` took it in.
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

        /** The locked connection, or `null` when gone or of another tenant. */
        public ?Connection $connection,

        /** The locked enforcement rule, under the default contract. */
        public ?LockedEnforcement $enforcement,

        /** The locked domain claim a reservation is bound to, if any. */
        public ?Domain $domain = null,

        /** The identity whose guard is held, if any. */
        public ?IdentityReference $guarded = null,

        /** The ids of every connection locked. */
        public array $lockedConnectionIds = [],

        /** Whether a `link`'s identity has ever held a verified domain link. */
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
     * Whether the locks were taken for exactly the result's tenant, connection
     * and application.
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
