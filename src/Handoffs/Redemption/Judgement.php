<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Redemption;

use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;

/**
 * What a purpose's rules came to at redemption, with what was judged under the
 * locks so nothing is read again after them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Judgement
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome  $outcome
     * @param  ?\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $linkProvenance
     * @param  ?string  $enforcementVersion
     */
    public function __construct(

        /** How the purpose's rules came out. */
        public RecheckOutcome $outcome,

        /** The linker's provenance of the link a `sign_in` passed through. */
        public ?LinkOrigin $linkProvenance = null,

        /** The enforcement version judged under the locks; `null` with no rule stored. */
        public ?string $enforcementVersion = null,
    ) {}

    /**
     * The rules came to the outcome, naming no link provenance.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome  $outcome
     * @return self
     */
    public static function of(RecheckOutcome $outcome): self
    {
        return new self($outcome);
    }

    /**
     * The same judgement under the given enforcement version.
     *
     * @param  ?string  $enforcementVersion
     * @return self
     */
    public function under(?string $enforcementVersion): self
    {
        return new self($this->outcome, $this->linkProvenance, $enforcementVersion);
    }
}
