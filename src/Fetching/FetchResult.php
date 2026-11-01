<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;

/**
 * How an outbound request ended (SSO-2.9): fetched, with the response's HTTP
 * status, headers and body; refused before it was sent (`fetch_refused`); or
 * failed once sent (`fetch_failed`). A refusal or failure carries its reason
 * code only: what went wrong in detail goes to the logs, never here.
 *
 * The body may hold provider tokens (a token response), so it is held in a
 * `\SensitiveParameterValue`: no dump (PHP's own, or the one behind Laravel's
 * `dump()`, which also lists private properties), export or array cast shows
 * it, and the result refuses to be serialised (SSO-7.6).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FetchResult
{
    /** @var ?\SensitiveParameterValue The response's body, for `fetched` only. */
    private ?\SensitiveParameterValue $body;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus  $status
     * @param  ?int  $statusCode
     * @param  array<string, string>  $headers
     * @param  ?string  $body
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** How the request ended. */
        public FetchStatus $status,

        /** The response's HTTP status code, for `fetched` only. */
        public ?int $statusCode = null,

        /** The response's headers, by lower-case name, for `fetched` only. */
        private array $headers = [],

        // Not promoted: held wrapped, so no dump, export or array cast shows it
        #[\SensitiveParameter]
        ?string $body = null,

        /** Why the request was refused or failed: `fetch_refused` or `fetch_failed`. */
        public ?FailureReason $reason = null,
    ) {
        $this->body = $body === null ? null : new \SensitiveParameterValue($body);
    }

    /**
     * What a dump shows: the status, the HTTP status code, the header names and
     * the reason, never the body.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'status'     => $this->status->value,
            'statusCode' => $this->statusCode,
            'headers'    => array_keys($this->headers),
            'body'       => $this->body === null ? null : '[redacted]',
            'reason'     => $this->reason?->value,
        ];
    }

    /**
     * Refuse to be serialised: a response lives only for the flow that asked
     * for it.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('Outbound responses cannot be serialised.');
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
        throw new \LogicException('Outbound responses cannot be unserialised.');
    }

    /**
     * A response was received within the caps, of whatever HTTP status.
     *
     * @param  int  $statusCode
     * @param  array<string, string>  $headers
     * @param  string  $body
     * @return self
     */
    public static function fetched(int $statusCode, array $headers, #[\SensitiveParameter] string $body): self
    {
        return new self(FetchStatus::FETCHED, $statusCode, array_change_key_case($headers, CASE_LOWER), $body);
    }

    /**
     * The request, or a redirect it was answered with, was refused before it
     * was sent.
     *
     * @return self
     */
    public static function refused(): self
    {
        return new self(FetchStatus::REFUSED, reason: FailureReason::FETCH_REFUSED);
    }

    /**
     * The request was sent and no acceptable response came back.
     *
     * @return self
     */
    public static function failed(): self
    {
        return new self(FetchStatus::FAILED, reason: FailureReason::FETCH_FAILED);
    }

    /**
     * Whether a response was received.
     *
     * @return bool
     */
    public function isFetched(): bool
    {
        return $this->status === FetchStatus::FETCHED;
    }

    /**
     * Whether a response was received with a `2xx` status.
     *
     * @return bool
     */
    public function isSuccessful(): bool
    {
        return $this->isFetched() && $this->statusCode >= 200 && $this->statusCode < 300;
    }

    /**
     * The response header of the name, whatever its case, or `null` when the
     * response has none.
     *
     * @param  string  $name
     * @return ?string
     */
    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    /**
     * The response's body, for `fetched` only.
     *
     * @return ?string
     */
    public function body(): ?string
    {
        $body = $this->body?->getValue();

        assert($body === null || is_string($body));

        return $body;
    }
}
