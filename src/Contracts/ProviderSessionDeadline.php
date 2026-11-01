<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Provider session deadline contract (SSO-6.10, SSO-9.10): whether the identity
 * provider's session deadline in a verified result limits the application's
 * session. SAML asks the service provider to end its security context at
 * `SessionNotOnOrAfter` (Profiles §4.1.4.3); an application that keeps its
 * sessions independent of the provider's binds its own answer.
 *
 * Asked by the completion pipeline for a result that carries a deadline; the
 * handoff carries the deadline as the session's latest end when the answer is
 * `limits_session`. The default, `Results\ProviderDeadlineLimitsSession`, says
 * it does. An implementation keeps nothing of one call for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ProviderSessionDeadline
{
    /**
     * Whether the result's provider session deadline limits the application's
     * session.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect
     */
    public function effect(VerifiedResult $result): DeadlineEffect;
}
