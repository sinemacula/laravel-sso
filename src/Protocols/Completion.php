<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;

/**
 * A driver's verdict on an identity provider response: verified claims, or a
 * refusal reason.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Completion
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Results\VerifiedClaims  $claims
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ReplayRecord  $replay
     * @param  ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     */
    private function __construct(

        /** What the driver verified, for a verified response. */
        public ?VerifiedClaims $claims,

        /** Why the response was refused, for a refused one. */
        public ?FailureReason $reason,

        /** What the completion records against replay, if anything. */
        public ?ReplayRecord $replay = null,

        /** Lets the response finish across a key removal its own validation made. */
        public ?TransitionReceipt $receipt = null,
    ) {}

    /**
     * The response passed every check.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedClaims  $claims
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ReplayRecord  $replay
     * @return self
     */
    public static function verified(VerifiedClaims $claims, ?ReplayRecord $replay = null): self
    {
        return new self($claims, null, $replay);
    }

    /**
     * The response was refused, for the reason given.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self(null, $reason);
    }

    /**
     * The completion with the given receipt; a refusal is returned unchanged.
     *
     * @param  ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     * @return self
     */
    public function withReceipt(?TransitionReceipt $receipt): self
    {
        return $this->claims === null || $receipt === null ? $this : new self($this->claims, null, $this->replay, $receipt);
    }

    /**
     * Whether the response passed every check.
     *
     * @return bool
     */
    public function isVerified(): bool
    {
        return $this->claims !== null;
    }

    /**
     * Whether the response was refused.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->reason !== null;
    }
}
