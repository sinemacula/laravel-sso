<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect;

/**
 * Default provider session deadline contract: the deadline always limits the
 * session, as SAML asks.
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
