<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use Carbon\CarbonImmutable;

/**
 * An identity's membership of a tenant as `Contracts\TenantMembership` answered
 * it (SSO-8.8): accepted by the person at a time, or not usable for linking
 * (missing, revoked, not accepted, or unknown).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MembershipStanding
{
    /**
     * Constructor.
     *
     * @param  ?\Carbon\CarbonImmutable  $acceptedAt
     */
    private function __construct(

        /** When the person accepted the current membership; `null` when no usable one exists. */
        public ?CarbonImmutable $acceptedAt = null,
    ) {}

    /**
     * A current membership the person accepted at the time given.
     *
     * @param  \Carbon\CarbonImmutable  $acceptedAt
     * @return self
     */
    public static function accepted(CarbonImmutable $acceptedAt): self
    {
        return new self($acceptedAt);
    }

    /**
     * No membership usable for linking: missing, revoked, not accepted or
     * unknown.
     *
     * @return self
     */
    public static function none(): self
    {
        return new self;
    }

    /**
     * Whether the membership was accepted strictly before the instant.
     *
     * @param  \Carbon\CarbonImmutable  $instant
     * @return bool
     */
    public function wasAcceptedBefore(CarbonImmutable $instant): bool
    {
        return $this->acceptedAt !== null && $this->acceptedAt->lessThan($instant);
    }
}
