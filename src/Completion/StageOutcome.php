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
 * The correlation step alone may instead hand the completion to re-initiation
 * (SSO-5.8): an unsolicited SAML response, with its correlation on the state,
 * at a connection whose driver re-initiates. Such an outcome neither proceeds
 * nor is refused; the pipeline runs no further step and answers it through
 * `Completion\UnsolicitedReinitiation`.
 *
 * The provisioning step alone may instead stop at the provisioning boundary
 * (SSO-8.6): a genuinely unlinked `sign_in` result holding no reservation. Such
 * an outcome neither proceeds nor is refused: the pipeline commits what the
 * completion has so far and offers the result to the unlinked-result event's
 * listeners, with no package transaction open, before its final continuation.
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
     * Hand the completion of an unsolicited response to re-initiation, with no
     * further step run.
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
