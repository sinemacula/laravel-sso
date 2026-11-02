<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;

/**
 * Link eligibility contract (SSO-8.5, SSO-5.11): whether an identity may link
 * through a connection, for example only as a member of the connection's
 * tenant. It is asked at a `link` flow's completion and again inside its
 * redemption's transaction, even when the subject is already linked to that
 * same identity.
 *
 * Protection through admission: an implementation that reads application state
 * either keeps its answer true until the redeemer's transaction commits, by a
 * guard its writers also take, or accepts that a change made after its answer
 * does not undo the link (`docs/design/linking.md`).
 *
 * The default, `Linking\RefusingLinkEligibility`, refuses every identity. An
 * implementation reads from the write connection (SSO-11.3), keeps nothing of
 * one call for the next (SSO-11.2), and lets an error propagate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LinkEligibility
{
    /**
     * Whether the identity may link through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict
     */
    public function judge(IdentityReference $identity, SsoConnection $connection): LinkEligibilityVerdict;
}
