<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Evidence;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The default evidence contract (SSO-8.7): nothing the provider asserted
 * counts, so the application's further factor is never satisfied by it.
 *
 * It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class InsufficientEvidence implements EvidencePolicy
{
    /**
     * Accept nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
     */
    #[\Override]
    public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): ?AcceptedEvidence
    {
        unset($result, $connection, $now);

        return null;
    }
}
