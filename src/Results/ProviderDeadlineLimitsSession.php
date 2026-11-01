<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect;

/**
 * The default provider session deadline contract (SSO-6.10): the identity
 * provider's session deadline always limits the application's session, as SAML
 * asks.
 *
 * It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProviderDeadlineLimitsSession implements ProviderSessionDeadline
{
    /**
     * The deadline limits the session.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect
     */
    #[\Override]
    public function effect(VerifiedResult $result): DeadlineEffect
    {
        unset($result);

        return DeadlineEffect::LIMITS_SESSION;
    }
}
