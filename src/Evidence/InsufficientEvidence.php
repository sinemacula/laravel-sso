<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Evidence;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The default evidence contract: nothing the provider asserted counts.
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
