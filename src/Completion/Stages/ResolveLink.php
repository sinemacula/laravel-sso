<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\Linker;

/**
 * The `link_resolution` step (SSO-8.2, SSO-8.6, SSO-8.8): the verified result's
 * link is resolved through the bound `Contracts\Linker`, by its connection,
 * issuer and subject alone, inside the completion's locked transaction, and in
 * its final continuation again. The `Links\LinkResolution` goes on with the
 * state, with the identity it resolves to, for the later steps to decide. It
 * never refuses.
 *
 * It holds the linking contract, which keeps nothing of one completion for the
 * next (SSO-11.2). A database error propagates (SSO-11.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResolveLink implements CompletionStage
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Linker  $linker
     */
    public function __construct(

        /** Resolves the identity a verified result is linked to. */
        private Linker $linker,
    ) {}

    /**
     * Resolve the result's link.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    #[\Override]
    public function run(CompletionState $state): StageOutcome
    {
        $result = $state->result ?? throw new \LogicException('A link is resolved once the result is verified.');

        return StageOutcome::proceed($state->withResolution($this->linker->resolve($result)));
    }
}
