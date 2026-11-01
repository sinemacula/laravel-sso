<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * Whether an attempt at a limited flow may go ahead (SSO-11.8): allowed, and
 * counted; or rate limited, with the seconds until it may be tried again and
 * nothing counted. Throttling is an outcome, never an exception; the flow
 * reports it with `reason` and answers with `retryAfter`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AttemptResult
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     */
    private function __construct(

        /** `rate_limited` for a refused attempt, `null` for an allowed one. */
        public ?FailureReason $reason = null,

        /** Seconds, at least 1, until the attempt may be tried again, for a refused attempt only. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * Every limit had room, and the attempt was counted against each.
     *
     * @return self
     */
    public static function allowed(): self
    {
        return new self;
    }

    /**
     * A limit is full for the seconds given, and nothing was counted.
     *
     * @param  int  $retryAfter
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function rateLimited(int $retryAfter): self
    {
        if ($retryAfter < 1) {
            throw new \InvalidArgumentException('A rate limited attempt waits at least one second.');
        }

        return new self(FailureReason::RATE_LIMITED, $retryAfter);
    }

    /**
     * Whether the attempt may go ahead.
     *
     * @return bool
     */
    public function isAllowed(): bool
    {
        return $this->reason === null;
    }

    /**
     * Whether the attempt was refused by a full limit.
     *
     * @return bool
     */
    public function isRateLimited(): bool
    {
        return $this->reason === FailureReason::RATE_LIMITED;
    }
}
