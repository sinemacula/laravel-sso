<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums\KeySelectionOutcome;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;

/**
 * The stored key that verifies an ID token, or why there is none, with the
 * receipt of any trust change the token's own refetch made.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeySelection
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums\KeySelectionOutcome  $outcome
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey  $key
     * @param  ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     */
    private function __construct(

        /** How the key was looked for. */
        public KeySelectionOutcome $outcome,

        /** The key, once found. */
        public ?ProviderKey $key = null,

        /** The receipt of the trust change the token's own refetch made, if any. */
        public ?TransitionReceipt $receipt = null,
    ) {}

    /**
     * The key was found.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey  $key
     * @return self
     */
    public static function found(ProviderKey $key): self
    {
        return new self(KeySelectionOutcome::FOUND, $key);
    }

    /**
     * No stored key is the token's; the JWKS may be refetched once.
     *
     * @return self
     */
    public static function unknown(): self
    {
        return new self(KeySelectionOutcome::UNKNOWN);
    }

    /**
     * The token is refused, with no refetch.
     *
     * @return self
     */
    public static function refused(): self
    {
        return new self(KeySelectionOutcome::REFUSED);
    }

    /**
     * A trust change overtook the refetch and no stored key is the token's.
     *
     * @return self
     */
    public static function overtaken(): self
    {
        return new self(KeySelectionOutcome::OVERTAKEN);
    }

    /**
     * Attach the receipt of the trust change the token's refetch made.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     * @return self
     */
    public function withReceipt(TransitionReceipt $receipt): self
    {
        return new self($this->outcome, $this->key, $receipt);
    }

    /**
     * Whether the key was found.
     *
     * @return bool
     *
     * @phpstan-assert-if-true !null $this->key
     */
    public function isFound(): bool
    {
        return $this->outcome === KeySelectionOutcome::FOUND;
    }

    /**
     * Whether no stored key is the token's, so the JWKS may be refetched.
     *
     * @return bool
     */
    public function isUnknown(): bool
    {
        return $this->outcome === KeySelectionOutcome::UNKNOWN;
    }

    /**
     * Whether a trust change overtook the refetch.
     *
     * @return bool
     */
    public function isOvertaken(): bool
    {
        return $this->outcome === KeySelectionOutcome::OVERTAKEN;
    }
}
