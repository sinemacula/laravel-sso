<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

use SineMacula\Laravel\Authentication\Proofs\Provenance;

/**
 * A stand-in for `laravel-authentication`'s real `Context\ContributionSubject`,
 * which this package does not install, with the exact signature of the
 * `provenance()` the guide's contributor reads
 * (`docs/guides/integrating-with-laravel-iam.md`): the session's external
 * provenance, or `null` for a session no external provider established. The
 * sibling's subject also carries the context, identity, principal, tenant and
 * session, and reads the provenance from the session's stored proofs; the
 * contributor reads none of those, so the stand-in is given the provenance.
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
     * The session's external provenance, or `null` for a session no external
     * provider established.
     *
     * @return ?\SineMacula\Laravel\Authentication\Proofs\Provenance
     */
    public function provenance(): ?Provenance
    {
        return $this->provenance;
    }
}
