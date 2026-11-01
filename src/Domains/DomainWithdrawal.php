<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * What happens, inside the same transaction, when a domain stops allowing
 * linking by email (SSO-3.3, SSO-8.8): its claim is removed, a recheck finds
 * its record missing or changed and suspends linking, or it lapses at the end
 * of its grace period. Every such change calls `linkingWithdrawn()` under the
 * locks it holds (the connection's row, then the domain's), before it writes,
 * so whatever depends on the domain's verification is withdrawn atomically with
 * it.
 *
 * Nothing depends on it yet, so it does nothing: linking by a verified domain
 * adds here the voiding of the domain's open link reservations, so a lapse, a
 * suspension or a removal can never leave one to be redeemed. It holds nothing
 * between calls (SSO-11.2). It is not final, so a test can observe the call.
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
     * Withdraw what depends on linking by the connection's domain. Called
     * inside the transaction that withdraws it, with the connection's and the
     * domain's rows locked.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @return void
     *
     * @SuppressWarnings("php:S1172")
     */
    public function linkingWithdrawn(Connection $connection, Domain $domain): void
    {
        // Nothing depends on a domain's verification yet
    }
}
