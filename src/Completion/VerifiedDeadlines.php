<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Linking\LinkingSettings;

/**
 * When a verified response stops being valid (SSO-8.6,
 * `docs/design/linking.md`): the earlier of its request's expiry and
 * `sso.linking.verified_result_max_age_seconds` from the moment it was
 * verified. A completion checks it under its locks, the provisioning helper
 * before its write, and the final continuation before it issues a handoff, so a
 * slow listener never finishes on an old response and no continuation extends a
 * request's authority.
 *
 * It holds the clock and the settings, neither of which keeps anything of one
 * completion for the next (SSO-11.2).
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
     * When a response verified now stops being valid, given its request's
     * expiry.
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
     * Whether the deadline has passed by now; a state not yet given one has
     * nothing to judge.
     *
     * @param  ?\Carbon\CarbonImmutable  $deadline
     * @return bool
     */
    public function hasPassed(?CarbonImmutable $deadline): bool
    {
        return $deadline !== null && $deadline <= $this->clock->now();
    }
}
