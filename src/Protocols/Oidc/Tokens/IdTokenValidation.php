<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Tokens;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;

/**
 * The outcome of validating an ID token: the token, or the refusal reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdTokenValidation
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken  $token
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     */
    private function __construct(

        /** The token, once validated. */
        public ?ValidatedIdToken $token,

        /** Why it was refused. */
        public ?FailureReason $reason,

        /** The receipt of any trust change made by this token's JWKS refetch. */
        public ?TransitionReceipt $receipt = null,
    ) {}

    /**
     * Create a validated outcome.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken  $token
     * @param  ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     * @return self
     */
    public static function validated(ValidatedIdToken $token, ?TransitionReceipt $receipt = null): self
    {
        return new self($token, null, $receipt);
    }

    /**
     * Create a refused outcome.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self(null, $reason);
    }

    /**
     * Whether the token passed every check.
     *
     * @return bool
     *
     * @phpstan-assert-if-true !null $this->token
     *
     * @phpstan-assert-if-false !null $this->reason
     */
    public function isValidated(): bool
    {
        return $this->token !== null;
    }
}
