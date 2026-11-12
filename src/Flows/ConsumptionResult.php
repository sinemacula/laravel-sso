<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\ConsumptionStatus;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;

/**
 * How consuming the authorisation request a response answers ended.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConsumptionResult
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\ConsumptionStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  ?\SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** How the consumption ended. */
        public ConsumptionStatus $status,

        /** The authorisation request, for every status but `unknown`. */
        public ?AuthorizationRequest $request = null,

        /** What the driver is given of the request, for a consumed one. */
        public ?ConsumedRequest $consumed = null,

        /** The registered application, when the completion may redirect to it. */
        public ?Application $application = null,

        /** Why the response may not go on, for every status but `consumed`. */
        public ?FailureReason $reason = null,
    ) {}

    /**
     * Dump without the request's columns or secrets.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'status'            => $this->status->value,
            'request_reference' => $this->request?->reference,
            'application'       => $this->application?->name,
            'reason'            => $this->reason?->value,
        ];
    }

    /**
     * Refuse to be serialised: it holds the consumed request.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A consumption result cannot be serialised.');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A consumption result cannot be unserialised.');
    }

    /**
     * The request was consumed now and the response may be validated.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @return self
     */
    public static function consumed(AuthorizationRequest $request, ConsumedRequest $consumed, Application $application): self
    {
        return new self(ConsumptionStatus::CONSUMED, $request, $consumed, $application);
    }

    /**
     * The request was consumed now but the response may not go on.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  ?\SineMacula\Laravel\Sso\Applications\Application  $application
     * @return self
     */
    public static function refused(FailureReason $reason, AuthorizationRequest $request, ?Application $application = null): self
    {
        return new self(ConsumptionStatus::REFUSED, $request, application: $application, reason: $reason);
    }

    /**
     * No request matches the response.
     *
     * @return self
     */
    public static function unknown(): self
    {
        return new self(ConsumptionStatus::UNKNOWN, reason: FailureReason::REQUEST_UNKNOWN);
    }

    /**
     * The request was consumed before.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return self
     */
    public static function replayed(AuthorizationRequest $request): self
    {
        return new self(ConsumptionStatus::REPLAYED, $request, reason: FailureReason::REQUEST_UNKNOWN);
    }

    /**
     * Whether the request was consumed now and the response may go on.
     *
     * @return bool
     */
    public function isConsumed(): bool
    {
        return $this->status === ConsumptionStatus::CONSUMED;
    }

    /**
     * Whether the request was consumed now but the response may not go on.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->status === ConsumptionStatus::REFUSED;
    }

    /**
     * Whether no request matches the response.
     *
     * @return bool
     */
    public function isUnknown(): bool
    {
        return $this->status === ConsumptionStatus::UNKNOWN;
    }

    /**
     * Whether the request was consumed before.
     *
     * @return bool
     */
    public function isReplayed(): bool
    {
        return $this->status === ConsumptionStatus::REPLAYED;
    }

    /**
     * Whether the request's application is still registered to redirect to.
     *
     * @return bool
     */
    public function hasRedirectTarget(): bool
    {
        return $this->application !== null;
    }
}
