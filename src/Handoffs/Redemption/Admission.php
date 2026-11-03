<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Redemption;

use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;

/**
 * What a redemption's checks and writes came to (SSO-9.9, SSO-9.10): `passed`
 * with the identity it established, the link that identity resolved through,
 * the evidence accepted of the result's own assertion and, for a `sign_in`, the
 * provenance that link held under the redemption's locks (as the linker stated
 * it, or as an activation made it), carried out so the link is never read
 * again; or the first check that refused it, which wrote nothing.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Admission
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome  $outcome
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $linkId
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     * @param  ?\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $linkProvenance
     */
    public function __construct(

        /** How it came out. */
        public RecheckOutcome $outcome,

        /** The identity it established, if any. */
        public ?IdentityReference $identity = null,

        /** The link the identity resolved through, if any. */
        public ?string $linkId = null,

        /** The evidence accepted of the result's own assertion, if any. */
        public ?AcceptedEvidence $evidence = null,

        /** The provenance of the link a `sign_in` established, under the locks, if stated. */
        public ?LinkOrigin $linkProvenance = null,
    ) {}

    /**
     * It was refused for the outcome.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome  $outcome
     * @return self
     */
    public static function refused(RecheckOutcome $outcome): self
    {
        return new self($outcome);
    }

    /**
     * Whether every check passed and every write was made.
     *
     * @return bool
     */
    public function isPassed(): bool
    {
        return $this->outcome === RecheckOutcome::PASSED;
    }
}
