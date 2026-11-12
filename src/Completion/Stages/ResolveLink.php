<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\Linker;

/**
 * The `link_resolution` step: resolves the result's link by connection, issuer
 * and subject alone; it never refuses.
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

        return StageOutcome::proceed($state->withResolution($this->linker->resolve($result, $state->client)));
    }
}
