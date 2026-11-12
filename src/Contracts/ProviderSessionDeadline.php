<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Decides whether the provider's session deadline in a verified result, such as
 * SAML's `SessionNotOnOrAfter`, limits the application's session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ProviderSessionDeadline
{
    /**
     * Asked only for a result that carries a deadline.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect
     */
    public function effect(VerifiedResult $result): DeadlineEffect;
}
