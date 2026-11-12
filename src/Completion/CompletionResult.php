<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;

/**
 * How a completion ended, for the application's controller to answer.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CompletionResult
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\Enums\CompletionStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?string  $redirectUri
     * @param  ?\SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery  $delivery
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @param  ?\SineMacula\Laravel\Sso\Handoffs\IssuedHandoff  $handoff
     * @param  ?int  $retryAfter
     * @param  ?string  $startUrl
     */
    private function __construct(

        /** How the completion ended. */
        public CompletionStatus $status,

        /** Why it did not complete, `rate_limited` included. */
        public ?FailureReason $reason = null,

        /** The application's redirect URI, for a completed or failed one. */
        public ?string $redirectUri = null,

        /** Where the code goes on the redirect URI, for a completed or failed one. */
        public ?HandoffDelivery $delivery = null,

        /** The request's public reference, for a completed or failed one. */
        public ?RequestReference $reference = null,

        /** The handoff issued, for a completed one. */
        public ?IssuedHandoff $handoff = null,

        /** Seconds, at least 1, until a rate limited one may be retried. */
        public ?int $retryAfter = null,

        /** The connection's start URL, for a re-initiated one. */
        public ?string $startUrl = null,
    ) {}

    /**
     * Dump everything but the code.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'status'       => $this->status->value,
            'reason'       => $this->reason?->value,
            'redirect_uri' => $this->redirectUri,
            'delivery'     => $this->delivery?->value,
            'reference'    => $this->reference?->value,
            'handoff'      => $this->handoff === null ? null : '[redacted]',
            'retry_after'  => $this->retryAfter,
            'start_url'    => $this->startUrl,
        ];
    }

    /**
     * Refuse to be serialised: it may hold the code.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A completion result cannot be serialised.');
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
        throw new \LogicException('A completion result cannot be unserialised.');
    }

    /**
     * A handoff code was issued for the application's redirect URI.
     *
     * @param  string  $redirectUri
     * @param  \SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery  $delivery
     * @param  \SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @param  \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff  $handoff
     * @return self
     */
    public static function completed(string $redirectUri, HandoffDelivery $delivery, RequestReference $reference, IssuedHandoff $handoff): self
    {
        return new self(CompletionStatus::COMPLETED, redirectUri: $redirectUri, delivery: $delivery, reference: $reference, handoff: $handoff);
    }

    /**
     * The flow failed with the application's redirect URI trusted.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  string  $redirectUri
     * @param  \SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery  $delivery
     * @param  \SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return self
     */
    public static function failed(FailureReason $reason, string $redirectUri, HandoffDelivery $delivery, RequestReference $reference): self
    {
        return new self(CompletionStatus::FAILED, $reason, $redirectUri, $delivery, $reference);
    }

    /**
     * The completion was refused with no trusted redirect target.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     */
    public static function rejected(FailureReason $reason): self
    {
        return new self(CompletionStatus::REJECTED, $reason);
    }

    /**
     * A limit is full for the seconds given.
     *
     * @param  int  $retryAfter
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function rateLimited(int $retryAfter): self
    {
        if ($retryAfter < 1) {
            throw new \InvalidArgumentException('A rate limited completion waits at least one second.');
        }

        return new self(CompletionStatus::RATE_LIMITED, FailureReason::RATE_LIMITED, retryAfter: $retryAfter);
    }

    /**
     * An unsolicited SAML response, answered with the connection's start URL.
     *
     * @param  string  $startUrl
     * @return self
     */
    public static function reinitiated(string $startUrl): self
    {
        return new self(CompletionStatus::REINITIATED, startUrl: $startUrl);
    }

    /**
     * Whether a handoff code was issued.
     *
     * @return bool
     */
    public function isCompleted(): bool
    {
        return $this->status === CompletionStatus::COMPLETED;
    }

    /**
     * Whether the flow failed with a trusted redirect target.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->status === CompletionStatus::FAILED;
    }

    /**
     * Whether it was refused with no trusted redirect target.
     *
     * @return bool
     */
    public function isRejected(): bool
    {
        return $this->status === CompletionStatus::REJECTED;
    }

    /**
     * Whether a limit is full.
     *
     * @return bool
     */
    public function isRateLimited(): bool
    {
        return $this->status === CompletionStatus::RATE_LIMITED;
    }

    /**
     * Whether an unsolicited SAML response was answered with re-initiation.
     *
     * @return bool
     */
    public function isReinitiated(): bool
    {
        return $this->status === CompletionStatus::REINITIATED;
    }
}
