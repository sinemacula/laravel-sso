<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;

/**
 * How a driver judged the identity provider's response to an authorisation
 * request (SSO-5.6, SSO-6, SSO-7): verified, with what every check verified, or
 * refused with a reason.
 *
 * A driver answers `verified` only once every check of its protocol has passed
 * against the consumed request; the completion pipeline then builds the
 * `VerifiedResult` from the claims. Every refusal is a value: a malformed,
 * unsigned, expired or replayed response, an unsuccessful SAML status or an
 * OIDC `error` response.
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
     */
    private function __construct(

        /** What the driver verified, for a verified response. */
        public ?VerifiedClaims $claims,

        /** Why the response was refused, for a refused one. */
        public ?FailureReason $reason,
    ) {}

    /**
     * The response passed every check, with what they verified.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedClaims  $claims
     * @return self
     */
    public static function verified(VerifiedClaims $claims): self
    {
        return new self($claims, null);
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
