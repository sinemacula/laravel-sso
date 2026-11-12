<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Decides whether the provider's authentication context in a verified result
 * counts as evidence for the application's further factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EvidencePolicy
{
    /**
     * Judge the result's own assertion only; `null` for missing, malformed, old
     * or future-dated evidence. Never log a value.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
     */
    public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): ?AcceptedEvidence;
}
