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
 * the evidence accepted of the result's own assertion, for a `sign_in` the
 * provenance that link held under the redemption's locks (as the linker stated
 * it, or as an activation made it), and the version of the enforcement the
 * connection was judged by under those locks, carried out so neither is ever
 * read again; or the first check that refused it, which wrote nothing.
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

        /** The provenance of the link a `sign_in` established, under the locks, if stated. */
        public ?LinkOrigin $linkProvenance = null,

        /** The version of the enforcement judged under the redemption's locks, if it passed and the rule has one. */
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
     * The same admission, judged under the enforcement of the version given
     * when it passed; a refusal is kept as it is, carrying its outcome alone.
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
