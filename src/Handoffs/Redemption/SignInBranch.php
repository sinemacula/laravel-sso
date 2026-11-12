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
 * Judges and admits a `sign_in` redemption: a reserved code is activated, any
 * other needs its link exactly as observed at completion.
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

        $now = $this->linker->resolve($context->result, $context->client);

        return match (true) {
            self::isContinuous($now, $context->binding) => new Judgement(RecheckOutcome::PASSED, $now->origin),
            $now->isSuspended()                         => Judgement::of(RecheckOutcome::LINK_SUSPENDED),
            $now->isScopeUnknown()                      => Judgement::of(RecheckOutcome::PRINCIPAL_SCOPE_UNKNOWN),
            default                                     => Judgement::of(RecheckOutcome::LINK_CHANGED),
        };
    }

    /**
     * Activate any reservation, then ask for evidence once an identity is
     * established.
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
     * Whether the subject is still unlinked, or still on the same active link
     * for the same identity.
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
