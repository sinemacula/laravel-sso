<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * What a completion stage decided: proceed, refuse, hand over to re-initiation
 * (correlation only) or stop at the provisioning boundary (provisioning only).
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
     * @param  bool  $reinitiating
     * @param  bool  $provisioning
     */
    private function __construct(

        /** The state as the stage left it. */
        public CompletionState $state,

        /** Why the completion was refused, for a refusal. */
        public ?FailureReason $reason,

        /** Whether the completion is handed to re-initiation. */
        private bool $reinitiating = false,

        /** Whether the completion stops at the provisioning boundary. */
        private bool $provisioning = false,
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
     * Hand an unsolicited response to re-initiation.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return self
     */
    public static function reinitiate(CompletionState $state): self
    {
        return new self($state, null, true);
    }

    /**
     * Stop the completion at the provisioning boundary.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return self
     */
    public static function provision(CompletionState $state): self
    {
        return new self($state, null, provisioning: true);
    }

    /**
     * Whether the completion goes on.
     *
     * @return bool
     */
    public function isProceeding(): bool
    {
        return $this->reason === null && !$this->reinitiating && !$this->provisioning;
    }

    /**
     * Whether the completion stopped at the provisioning boundary.
     *
     * @return bool
     */
    public function isProvisioning(): bool
    {
        return $this->provisioning;
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

    /**
     * Whether the completion is handed to re-initiation.
     *
     * @return bool
     */
    public function isReinitiating(): bool
    {
        return $this->reinitiating;
    }
}
