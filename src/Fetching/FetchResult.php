<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;

/**
 * How an outbound request ended. The body may hold provider tokens, so no dump,
 * export or array cast shows it and the result cannot be serialised.
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

        /** Why the request was refused or failed. */
        public ?FailureReason $reason = null,
    ) {
        $this->body = $body === null ? null : new \SensitiveParameterValue($body);
    }

    /**
     * Show everything but the body and header values.
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
     * Refuse to be serialised; a response lives only for its flow.
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
     * A response of any HTTP status received within the caps.
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
     * The request or a redirect was refused before it was sent.
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
     * The named response header, case-insensitively, or `null`.
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
