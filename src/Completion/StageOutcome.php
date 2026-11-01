<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * What a completion stage decided (SSO-5.6): proceed to the next step with the
 * state as it left it, or refuse the completion with a reason, with the state
 * as far as the completion got, so the refusal is reported with what was
 * established (the connection, the request's reference, the identity) and
 * redirected to the application's URI once a request was found.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class StageOutcome
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The state as the stage left it. */
        public CompletionState $state,

        /** Why the completion was refused, for a refusal. */
        public ?FailureReason $reason,
    ) {}

    /**
     * Go on to the next step.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return self
     */
    public static function proceed(CompletionState $state): self
    {
        return new self($state, null);
    }

    /**
     * Refuse the completion, for the reason given.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     */
    public static function refuse(CompletionState $state, FailureReason $reason): self
    {
        return new self($state, $reason);
    }

    /**
     * Whether the completion goes on.
     *
     * @return bool
     */
    public function isProceeding(): bool
    {
        return $this->reason === null;
    }

    /**
     * Whether the completion was refused.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->reason !== null;
    }
}
