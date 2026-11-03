<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Redemption;

use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;

/**
 * What a purpose's rules came to at redemption (SSO-9.9, SSO-9.10): the
 * outcome, for a `sign_in` that passed through an existing link that link's
 * provenance as the linker stated it under the redemption's locks, and the
 * version of the enforcement the connection was judged by under those locks.
 * The admission carries both out with the link's id, so neither the package nor
 * an adapter reads the link or the rule again once the locks are released, when
 * a confirming `link` or a rule change may already have changed them.
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

        /** The provenance of the link judged, for a `sign_in` that passed through one the linker stated it of. */
        public ?LinkOrigin $linkProvenance = null,

        /** The version of the enforcement judged under the redemption's locks, `null` while the rule has none stored. */
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
     * The same judgement, made under the enforcement of the version given.
     *
     * @param  ?string  $enforcementVersion
     * @return self
     */
    public function under(?string $enforcementVersion): self
    {
        return new self($this->outcome, $this->linkProvenance, $enforcementVersion);
    }
}
