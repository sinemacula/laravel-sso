<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

use SineMacula\Laravel\Authentication\Proofs\Provenance;

/**
 * A stand-in for `laravel-authentication`'s `Context\ContributionSubject`,
 * modelling only the `provenance()` the guide's contributor reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ContributionSubject
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Provenance  $provenance
     */
    public function __construct(

        /** The session's external provenance, if any. */
        private ?Provenance $provenance = null,
    ) {}

    /**
     * The session's external provenance, or `null` when it has none.
     *
     * @return ?\SineMacula\Laravel\Authentication\Proofs\Provenance
     */
    public function provenance(): ?Provenance
    {
        return $this->provenance;
    }
}
