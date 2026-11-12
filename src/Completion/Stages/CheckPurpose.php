<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\Rules\LinkRules;
use SineMacula\Laravel\Sso\Completion\Rules\ReauthenticationRules;
use SineMacula\Laravel\Sso\Completion\Rules\SignInRules;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;

/**
 * The `purpose_rules` step: what the flow's purpose requires of the resolved
 * link, by the purpose's rules class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CheckPurpose implements CompletionStage
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves the rules of the flow's purpose. */
        private Container $container,
    ) {}

    /**
     * Refuse for what the purpose's rules answer, and go on otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    #[\Override]
    public function run(CompletionState $state): StageOutcome
    {
        $consumed = $state->consumed ?? throw new \LogicException('A purpose\'s rules are checked once the request is consumed.');
        $rules    = match ($consumed->purpose) {
            Purpose::SIGN_IN        => $this->container->make(SignInRules::class),
            Purpose::LINK           => $this->container->make(LinkRules::class),
            Purpose::REAUTHENTICATE => $this->container->make(ReauthenticationRules::class),
        };
        $reason = $rules->refusal($state);

        return $reason === null ? StageOutcome::proceed($state) : StageOutcome::refuse($state, $reason);
    }
}
