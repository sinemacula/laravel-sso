<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Application;

use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;

/**
 * The example application's link eligibility (SSO-8.5): every identity may link
 * through every connection. The package's default refuses every identity, so a
 * `link` flow is refused until an application binds its own; an application
 * that limits linking (to its members, to a tenant's connections) answers
 * `ineligible` where it does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EveryoneMayLink implements LinkEligibility
{
    /**
     * Let the identity link.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict
     */
    #[\Override]
    public function judge(IdentityReference $identity, SsoConnection $connection): LinkEligibilityVerdict
    {
        unset($identity, $connection);

        return LinkEligibilityVerdict::ELIGIBLE;
    }
}
