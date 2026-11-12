<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * Withdraws what depends on a domain, in the same transaction, when it stops
 * allowing linking by email.
 *
 * Not final, so a test can observe the call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 */
readonly class DomainWithdrawal
{
    /**
     * Delete the domain's open link reservations; call with the connection's
     * and then the domain's rows locked, before writing.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @return void
     */
    public function linkingWithdrawn(Connection $connection, Domain $domain): void
    {
        ReservationWithdrawal::ofDomain($connection, $domain);
    }
}
