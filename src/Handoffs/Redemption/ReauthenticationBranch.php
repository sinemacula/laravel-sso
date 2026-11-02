<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Redemption;

use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\PurposeBranch;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Links\LinkResolution;

/**
 * A `reauthenticate` at redemption (SSO-5.10, SSO-9.5, SSO-9.9): only through
 * the caller's transaction (`HandoffRedemption::admit()`), since its write and
 * its session's lock must commit together. The subject must still resolve
 * through the exact link observed at completion, to the identity the flow was
 * started for: a suspended link is `link_suspended`, and anything else
 * `identity_mismatch`. The session must then be active, of the application and
 * the connection, and bound to exactly that link, with its row locked through
 * the write (`Contracts\ReauthenticationSessions::lockedStanding()`), or it is
 * `session_ineligible`.
 *
 * A result stating no authentication time renews nothing, and is
 * `authentication_expired` before the session is asked about. The package's
 * completion never issues a code from one
 * (`Completion\Rules\ReauthenticationRules`), but an adapter that redeems its
 * own codes hands `Handoffs\HandoffRecheck` its own result, so this is
 * reachable and a refusal rather than an error. `admit()` runs only once
 * `judge()` passed for the same result, so the time is there by then.
 *
 * Admission renews the session's authentication time from the provider's, with
 * any evidence newly accepted from this authentication, and nothing else: no
 * lifetime, refresh token, sign-in provenance or earlier evidence changes
 * (SSO-9.5). It acknowledges no sign-in, activates no reservation and creates
 * no link.
 *
 * It holds the linker, the sessions, the policy and the clock, none of which
 * keeps anything of one redemption for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReauthenticationBranch implements PurposeBranch
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Linker  $linker
     * @param  \SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions  $sessions
     * @param  \SineMacula\Laravel\Sso\Contracts\EvidencePolicy  $evidence
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Resolves the result's link now. */
        private Linker $linker,

        /** Locks the session and renews its authentication time. */
        private ReauthenticationSessions $sessions,

        /** Whether the result's own assertion counts as evidence. */
        private EvidencePolicy $evidence,

        /** The clock the evidence is judged at. */
        private Clock $clock,
    ) {}

    /**
     * Judge the exact link, that the result states when the provider
     * authenticated, and the session bound to that link.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     */
    #[\Override]
    public function judge(RedemptionContext $context): RecheckOutcome
    {
        $now = $this->linker->resolve($context->result);

        return match (true) {
            $now->isSuspended()                                               => RecheckOutcome::LINK_SUSPENDED,
            $now->isScopeUnknown()                                            => RecheckOutcome::PRINCIPAL_SCOPE_UNKNOWN,
            !self::isExactLink($now, $context)                                => RecheckOutcome::IDENTITY_MISMATCH,
            $context->result->authenticationContext->authenticatedAt === null => RecheckOutcome::AUTHENTICATION_EXPIRED,
            default                                                           => $this->standing($context, (string) $now->linkId),
        };
    }

    /**
     * Renew the session's authentication time, with the evidence accepted.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Admission
     *
     * @throws \LogicException
     */
    #[\Override]
    public function admit(RedemptionContext $context): Admission
    {
        $binding       = $context->binding;
        $identity      = $binding->identity                                       ?? throw new \LogicException('A reauthenticate flow names the identity it was started for.');
        $session       = $binding->sessionId                                      ?? throw new \LogicException('A reauthenticate flow names the session it was started on.');
        $authenticated = $context->result->authenticationContext->authenticatedAt ?? throw new \LogicException('A reauthenticate result states when the provider authenticated.');
        $evidence      = $this->evidence->evaluate($context->result, $context->connection, $this->clock->now());

        $this->sessions->renewAuthentication($identity, $session, $authenticated, $evidence);

        return new Admission(RecheckOutcome::PASSED, $identity, $binding->linkId, $evidence);
    }

    /**
     * Whether the subject resolves to the flow's identity through the link
     * observed at completion.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $now
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return bool
     */
    private static function isExactLink(LinkResolution $now, RedemptionContext $context): bool
    {
        $binding = $context->binding;

        return $binding->identity !== null
            && $now->isLinked()
            && $now->isHeldBy($binding->identity)
            && $now->linkId === $binding->linkId;
    }

    /**
     * Whether the session is active and bound to exactly the link, locked.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @param  string  $linkId
     * @return \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     *
     * @throws \LogicException
     */
    private function standing(RedemptionContext $context, string $linkId): RecheckOutcome
    {
        $binding  = $context->binding;
        $identity = $binding->identity  ?? throw new \LogicException('A reauthenticate flow names the identity it was started for.');
        $session  = $binding->sessionId ?? throw new \LogicException('A reauthenticate flow names the session it was started on.');
        $standing = $this->sessions->lockedStanding($identity, $session, $context->result->application, $context->connection, $linkId);

        return $standing->isSignedIn() ? RecheckOutcome::PASSED : RecheckOutcome::SESSION_INELIGIBLE;
    }
}
