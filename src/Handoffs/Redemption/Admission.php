<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Redemption;

use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;

/**
 * What a redemption's checks and writes came to, carrying out what was judged
 * under the locks so it is never read again.
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
     * @param  ?string  $enforcementVersion
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

        /** The provenance of the link a `sign_in` established, if stated. */
        public ?LinkOrigin $linkProvenance = null,

        /** The enforcement version judged under the locks, if it passed. */
        public ?string $enforcementVersion = null,
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
     * The same admission under the given enforcement version; a refusal is kept
     * as it is.
     *
     * @param  ?string  $enforcementVersion
     * @return self
     */
    public function under(?string $enforcementVersion): self
    {
        if (!$this->isPassed()) {
            return $this;
        }

        return new self($this->outcome, $this->identity, $this->linkId, $this->evidence, $this->linkProvenance, $enforcementVersion);
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
