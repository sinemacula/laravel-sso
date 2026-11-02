<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Evidence contract (SSO-8.7, SSO-9.5): whether the identity provider's
 * authentication context, as the result's own validated assertion stated it,
 * counts as evidence for the application's further factor. It is asked at
 * redemption, by current policy and against the provider's authentication time;
 * a code's short lifetime never establishes evidence freshness.
 *
 * Missing, malformed, unaccepted, excessively old or impermissibly future-dated
 * evidence is insufficient, `null`, never a pass, and a `link` result is never
 * asked. Accepted evidence is an input to the application's policy for further
 * factors, never an automatic pass, and is never strengthened from UserInfo or
 * another assertion.
 *
 * Protection through admission: it reads a policy, which it answers from
 * current state; the redeemer stores the evidence it accepted in its own
 * transaction.
 *
 * The default, `Evidence\InsufficientEvidence`, accepts nothing, and
 * `Evidence\ConnectionEvidencePolicy` is what an application binds to judge
 * each connection's stored policy. An implementation keeps nothing of one call
 * for the next (SSO-11.2), never logs a value, and lets an error propagate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EvidencePolicy
{
    /**
     * The evidence the result's own assertion gives at the instant, or `null`
     * when what it gives is insufficient.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
     */
    public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): ?AcceptedEvidence;
}
