<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Redemption;

use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;

/**
 * What a purpose's rules came to at redemption (SSO-9.9, SSO-9.10): the
 * outcome, and for a `sign_in` that passed through an existing link, that
 * link's provenance as the linker stated it under the redemption's locks. The
 * admission carries that provenance out with the link's id, so neither the
 * package nor an adapter reads the link again once the locks are released, when
 * a confirming `link` may already have changed it.
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
     */
    public function __construct(

        /** How the purpose's rules came out. */
        public RecheckOutcome $outcome,

        /** The provenance of the link judged, for a `sign_in` that passed through one the linker stated it of. */
        public ?LinkOrigin $linkProvenance = null,
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
}
