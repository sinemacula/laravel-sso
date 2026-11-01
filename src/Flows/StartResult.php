<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\StartStatus;
use SineMacula\Laravel\Sso\Protocols\Navigation;

/**
 * The answer to a start of an authorisation request (SSO-5.1, SSO-3.4,
 * SSO-12.5): started, with the request's public reference, the typed navigation
 * and, when the client sent no challenge, the verifier the package generated,
 * returned once; refused, with a reason; or rate limited, with `retryAfter`.
 *
 * `body()` is the start response's body, `{reference, navigation, verifier?}`,
 * and is the one place the generated verifier is revealed; `headers()` are the
 * headers that response is sent with, `Cache-Control: no-store` whenever it
 * carries a verifier and on every other answer too (SSO-9.8). A discovery miss
 * answers exactly this shape (SSO-3.5). A dump never shows the verifier, nor
 * the navigation's query values or form field values (the state, the nonce, a
 * `SAMLRequest`), which only `body()` carries; the result refuses to be
 * serialised.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class StartResult
{
    /** @var array<string, string> The headers every start response is sent with. */
    public const array HEADERS = ['Cache-Control' => 'no-store'];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\StartStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Navigation  $navigation
     * @param  ?\SineMacula\Laravel\Sso\Flows\Verifier  $verifier
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     */
    private function __construct(

        /** How the start ended. */
        public StartStatus $status,

        /** The request's public reference, for a started one. */
        public ?RequestReference $reference = null,

        /** Where the client sends the browser, for a started one. */
        public ?Navigation $navigation = null,

        /** The verifier the package generated, for a started one whose client sent no challenge. */
        public ?Verifier $verifier = null,

        /** Why it was refused, `rate_limited` included. */
        public ?FailureReason $reason = null,

        /** Seconds, at least 1, until it may be tried again, for a rate limited one. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * What a dump shows: never the verifier, and the navigation as its own dump
     * shows it, never a query value or a field's value.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'status'      => $this->status->value,
            'reference'   => $this->reference?->value,
            'navigation'  => $this->navigation?->__debugInfo(),
            'verifier'    => $this->verifier === null ? null : '[redacted]',
            'reason'      => $this->reason?->value,
            'retry_after' => $this->retryAfter,
        ];
    }

    /**
     * Refuse to be serialised: it may carry the verifier.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A start result cannot be serialised.');
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
        throw new \LogicException('A start result cannot be unserialised.');
    }

    /**
     * The client is sent on with the reference, and the verifier when the
     * package generated one.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @param  \SineMacula\Laravel\Sso\Protocols\Navigation  $navigation
     * @param  ?\SineMacula\Laravel\Sso\Flows\Verifier  $verifier
     * @return self
     */
    public static function started(RequestReference $reference, Navigation $navigation, ?Verifier $verifier = null): self
    {
        return new self(StartStatus::STARTED, $reference, $navigation, $verifier);
    }

    /**
     * The start was refused, for any reason but throttling.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function refused(FailureReason $reason): self
    {
        if ($reason === FailureReason::RATE_LIMITED) {
            throw new \InvalidArgumentException('A rate limited start is answered by rateLimited(), with its wait.');
        }

        return new self(StartStatus::REFUSED, reason: $reason);
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
            throw new \InvalidArgumentException('A rate limited start waits at least one second.');
        }

        return new self(StartStatus::RATE_LIMITED, reason: FailureReason::RATE_LIMITED, retryAfter: $retryAfter);
    }

    /**
     * Whether the client is sent on.
     *
     * @return bool
     */
    public function isStarted(): bool
    {
        return $this->status === StartStatus::STARTED;
    }

    /**
     * Whether the start was refused for a reason other than throttling.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->status === StartStatus::REFUSED;
    }

    /**
     * Whether the start was refused by a full limit.
     *
     * @return bool
     */
    public function isRateLimited(): bool
    {
        return $this->status === StartStatus::RATE_LIMITED;
    }

    /**
     * The start response's body (SSO-12.5): `{reference, navigation,
     * verifier?}` for a started one, revealing the generated verifier; the
     * `error` code, and `retry_after` for a rate limited one, otherwise.
     *
     * @return array<string, mixed>
     */
    public function body(): array
    {
        if ($this->reference === null || $this->navigation === null) {
            return array_filter(['error' => $this->reason?->value, 'retry_after' => $this->retryAfter], static fn (mixed $value): bool => $value !== null);
        }

        $body = ['reference' => $this->reference->value, 'navigation' => $this->navigation->jsonSerialize()];

        if ($this->verifier !== null) {
            $body['verifier'] = $this->verifier->reveal();
        }

        return $body;
    }

    /**
     * The headers the start response is sent with: `Cache-Control: no-store`,
     * and `Retry-After` for a rate limited one.
     *
     * @return array<string, string>
     */
    public function headers(): array
    {
        return $this->retryAfter === null ? self::HEADERS : [...self::HEADERS, 'Retry-After' => (string) $this->retryAfter];
    }
}
