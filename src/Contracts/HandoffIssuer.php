<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;

/**
 * Handoff issuer contract (SSO-9.2, AUTH-3.10): issues the single-use,
 * short-lived code that carries a verified result from the API to the client
 * that started the flow, bound to every part of the grant: the purpose, the
 * application, the connection, the request's public reference, the S256
 * challenge of the client's verifier, the identity the result's link resolved
 * to, the identity of a `link` or `reauthenticate` flow and the session of a
 * `reauthenticate` flow.
 *
 * The completion pipeline asks it once per completed flow, inside the
 * completion's transaction on the storage connection, after rechecking that the
 * application allows sign-in through an external provider; an implementation
 * that writes elsewhere is not atomic with the completion (decision D5). A code
 * is stored only as a hash, is single-use, and lives until the grant's expiry
 * (60 seconds by default, at most 300). An implementation signals failure by
 * throwing, which refuses the completion as a server error (SSO-11.4); it never
 * answers a code it did not store.
 *
 * The default, `Handoffs\DatabaseHandoffStore`, is the package's own store,
 * which the package's redemption helper redeems; under `laravel-iam` it is
 * bound to `laravel-authentication`'s handoff codes, so there is one kind of
 * code, redeemed by purpose (SSO-9.9). An implementation keeps nothing of one
 * call for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HandoffIssuer
{
    /**
     * Issue a code for the grant.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffGrant  $grant
     * @return \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff
     */
    public function issue(HandoffGrant $grant): IssuedHandoff;
}
