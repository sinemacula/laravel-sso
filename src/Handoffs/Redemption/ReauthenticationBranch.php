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
 * Judges and admits a `reauthenticate` redemption, which renews only the
 * session's authentication time and evidence.
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
     * Judge the exact link, the authentication time and the session bound to
     * the link; an adapter's own result may lack the time, so that refuses.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Judgement
     */
    #[\Override]
    public function judge(RedemptionContext $context): Judgement
    {
        $now = $this->linker->resolve($context->result, $context->client);

        return Judgement::of(match (true) {
            $now->isSuspended()                                               => RecheckOutcome::LINK_SUSPENDED,
            $now->isScopeUnknown()                                            => RecheckOutcome::PRINCIPAL_SCOPE_UNKNOWN,
            !self::isExactLink($now, $context)                                => RecheckOutcome::IDENTITY_MISMATCH,
            $context->result->authenticationContext->authenticatedAt === null => RecheckOutcome::AUTHENTICATION_EXPIRED,
            default                                                           => $this->standing($context, (string) $now->linkId),
        });
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
     * Whether the subject resolves to the flow's identity through the observed
     * link.
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
     * Lock the session and judge it active and bound to exactly the link.
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
