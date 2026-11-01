<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Secrets;

/**
 * What a helper returns for a stored client secret (SSO-2.5): whether one is
 * set, and nothing of it. Once set, a secret is never read back; an application
 * that has lost it sets a new one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MaskedSecret implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  bool  $isSet
     */
    private function __construct(

        /** Whether a secret is stored. */
        public bool $isSet,
    ) {}

    /**
     * A secret is stored.
     *
     * @return self
     */
    public static function set(): self
    {
        return new self(true);
    }

    /**
     * No secret is stored.
     *
     * @return self
     */
    public static function unset(): self
    {
        return new self(false);
    }

    /**
     * Whether a secret is stored, under `set`.
     *
     * @return array{set: bool}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['set' => $this->isSet];
    }
}
