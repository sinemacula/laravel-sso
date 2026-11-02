<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Tokens;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;

/**
 * How an ID token was judged (SSO-7.3, SSO-7.4): validated, with the token and
 * the receipt of the trust change its own refetch made, if any, or refused with
 * a reason.
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

        /** Why it was refused, for a refused one. */
        public ?FailureReason $reason,

        /** The receipt of the trust change the token's own refetch made, for a validated token. */
        public ?TransitionReceipt $receipt = null,
    ) {}

    /**
     * The token passed every check.
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
     * The token was refused, for the reason given.
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
