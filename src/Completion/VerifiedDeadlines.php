<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Linking\LinkingSettings;

/**
 * When a verified response stops being valid, so no continuation extends a
 * request's authority.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class VerifiedDeadlines
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Linking\LinkingSettings  $settings
     */
    public function __construct(

        /** The clock the response is verified at. */
        private Clock $clock,

        /** How long a verified response may keep finishing. */
        private LinkingSettings $settings,
    ) {}

    /**
     * When a response verified now stops being valid: the maximum age, capped
     * by the request's expiry.
     *
     * @param  ?\Carbon\CarbonImmutable  $requestExpiry
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    public function until(?CarbonImmutable $requestExpiry): CarbonImmutable
    {
        $bounded = $this->clock->now()->addSeconds($this->settings->verifiedResultMaxAgeSeconds());

        return $requestExpiry === null ? $bounded : $bounded->min($requestExpiry);
    }

    /**
     * Whether the deadline has passed; no deadline never has.
     *
     * @param  ?\Carbon\CarbonImmutable  $deadline
     * @return bool
     */
    public function hasPassed(?CarbonImmutable $deadline): bool
    {
        return $deadline !== null && $deadline <= $this->clock->now();
    }
}
