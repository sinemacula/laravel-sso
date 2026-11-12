<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * What the link email contract found; an ambiguous match links nothing and
 * names no one.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkEmailMatch
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  bool  $ambiguous
     */
    private function __construct(

        /** The one identity matched. */
        public ?IdentityReference $identity = null,

        /** Whether more than one matched. */
        public bool $ambiguous = false,
    ) {}

    /**
     * No identity matched.
     *
     * @return self
     */
    public static function none(): self
    {
        return new self;
    }

    /**
     * Exactly the identity matched.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return self
     */
    public static function exactlyOne(IdentityReference $identity): self
    {
        return new self($identity);
    }

    /**
     * More than one identity matched.
     *
     * @return self
     */
    public static function ambiguous(): self
    {
        return new self(ambiguous: true);
    }

    /**
     * Whether the identity is the sole match, compared byte for byte.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     */
    public function isSolely(IdentityReference $identity): bool
    {
        return $this->identity?->is($identity) ?? false;
    }
}
