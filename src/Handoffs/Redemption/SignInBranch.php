<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Redemption;

use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\PurposeBranch;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Links\LinkResolution;

/**
 * A `sign_in` at redemption (SSO-8.2, SSO-8.8, SSO-9.9):
 *
 * - a code bound to a reservation is judged and activated by
 *   `Linking\ReservationActivation`, and nothing else: a missing or invalid
 *   reservation is `reservation_invalid`, never a fallback to provisioning or
 *   an unlinked handoff;
 * - a code that resolved to a link needs that same link still there, by its id,
 *   for that same identity: a suspended one is `link_suspended`, one whose
 *   scope could not be judged `principal_scope_unknown`, and anything else
 *   `link_changed`;
 * - an unlinked handoff needs the subject still absent, and a code that
 *   observed a link for no identity is never one: the same refusals follow.
 *
 * Accepted evidence is asked of the bound policy (`Contracts\EvidencePolicy`)
 * once, at redemption and after any activation, and only once an identity is
 * established: an unlinked handoff and a refusal never ask.
 *
 * The admission carries out the provenance of the link it established
 * (SSO-9.10): for an existing link, what the linker stated of it in `judge()`,
 * under the locks; for an activated reservation, what the activation made it.
 * Neither is read again afterwards.
 *
 * It holds the linker, the activation, the policy and the clock, none of which
 * keeps anything of one redemption for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignInBranch implements PurposeBranch
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Linker  $linker
     * @param  \SineMacula\Laravel\Sso\Linking\ReservationActivation  $activation
     * @param  \SineMacula\Laravel\Sso\Contracts\EvidencePolicy  $evidence
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Resolves the result's link now. */
        private Linker $linker,

        /** Judges and activates a reservation. */
        private ReservationActivation $activation,

        /** Whether the result's own assertion counts as evidence. */
        private EvidencePolicy $evidence,

        /** The clock the evidence is judged at. */
        private Clock $clock,
    ) {}

    /**
     * Judge the code's reservation, or the continuity of its link.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Judgement
     */
    #[\Override]
    public function judge(RedemptionContext $context): Judgement
    {
        if ($context->binding->reservationId !== null) {
            return Judgement::of($this->activation->judge($context));
        }

        $now = $this->linker->resolve($context->result);

        return match (true) {
            self::isContinuous($now, $context->binding) => new Judgement(RecheckOutcome::PASSED, $now->origin),
            $now->isSuspended()                         => Judgement::of(RecheckOutcome::LINK_SUSPENDED),
            $now->isScopeUnknown()                      => Judgement::of(RecheckOutcome::PRINCIPAL_SCOPE_UNKNOWN),
            default                                     => Judgement::of(RecheckOutcome::LINK_CHANGED),
        };
    }

    /**
     * Activate the code's reservation, if it holds one, and answer the identity
     * it established, its link with that link's provenance, and the evidence
     * accepted.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Admission
     */
    #[\Override]
    public function admit(RedemptionContext $context): Admission
    {
        $binding  = $context->binding;
        $identity = $binding->linkedIdentity;
        $linkId   = $binding->linkId;
        $origin   = $context->linkProvenance;

        if ($binding->reservationId !== null) {
            [$identity, $linkId, $origin] = $this->activation->activate($context);
        }

        $evidence = $identity === null ? null : $this->evidence->evaluate($context->result, $context->connection, $this->clock->now());

        return new Admission(RecheckOutcome::PASSED, $identity, $linkId, $evidence, $origin);
    }

    /**
     * Whether the link is as the code was bound to it: a subject still absent
     * for an unlinked handoff, or that same link, active, for that same
     * identity.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $now
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $before
     * @return bool
     */
    private static function isContinuous(LinkResolution $now, HandoffBinding $before): bool
    {
        if ($before->linkedIdentity === null) {
            return $before->linkId === null && $now->isAbsent();
        }

        return $now->isLinked() && $now->isHeldBy($before->linkedIdentity) && $now->linkId === $before->linkId;
    }
}
