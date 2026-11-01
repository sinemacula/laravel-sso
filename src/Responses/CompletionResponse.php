<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Responses;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Response;

/**
 * The response a completion at an assertion consumer service or a callback
 * answers with (SSO-5.6, SSO-5.7, SSO-12.1), as `CompletionResponses::from()`
 * builds it: a status, the headers, the `Location` of a redirect and a plain
 * text body.
 *
 * A redirect is a `302` or a `303`, never a `307` or a `308`, which would
 * forward the posted body. A refusal is a `400`, or a `429` with `Retry-After`,
 * and has no `Location`. Every response is sent with `Cache-Control: no-store`,
 * `Referrer-Policy: no-referrer` and a plain text `Content-Type`, since the
 * `Location` of a completed one carries the handoff code (SSO-9.8).
 *
 * The `Location` is held in a `\SensitiveParameterValue` and leaves the object
 * only through `location()` and `toResponse()`: a dump and `json_encode()` show
 * it with the code redacted, and the response refuses to be serialised or
 * unserialised, so the code never reaches a log, a cache, a queue or an event.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CompletionResponse implements \JsonSerializable, Responsable
{
    /** @var array<string, string> The headers every completion response is sent with. */
    public const array HEADERS = [
        'Cache-Control'   => 'no-store',
        'Referrer-Policy' => 'no-referrer',
        'Content-Type'    => 'text/plain; charset=UTF-8',
    ];

    /** @var int The status of a redirect after a GET: `302 Found`. */
    public const int FOUND = 302;

    /** @var int The status of a redirect after a POST or any other method: `303 See Other`. */
    public const int SEE_OTHER = 303;

    /** @var int The status of a completion with no trusted redirect target. */
    public const int BAD_REQUEST = 400;

    /** @var int The status of a completion refused by a full limit. */
    public const int TOO_MANY_REQUESTS = 429;

    /** @var string What a dump shows in place of the handoff code. */
    private const string REDACTED = '[redacted]';

    /** @var string The value of a `code` parameter in a query or a fragment. */
    private const string CODE_VALUE = '/(?<=[?#&]code=)[^&#]*/';

    /** @var \SensitiveParameterValue The `Location` of a redirect, or null. */
    private \SensitiveParameterValue $location;

    /**
     * Constructor.
     *
     * @param  int  $status
     * @param  array<string, string>  $headers
     * @param  string  $body
     * @param  ?string  $location
     */
    private function __construct(

        /** The HTTP status. */
        public int $status,

        /** The headers, `Location` aside. */
        public array $headers,

        /** The plain text body, for a client that shows it. */
        public string $body,

        // The `Location` of a redirect, which may carry the handoff code; held
        // wrapped.
        #[\SensitiveParameter]
        ?string $location = null,
    ) {
        $this->location = new \SensitiveParameterValue($location);
    }

    /**
     * What a dump shows: the `Location` with the handoff code redacted.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    /**
     * Refuse to be serialised: the `Location` may carry the handoff code.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A completion response cannot be serialised.');
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
        throw new \LogicException('A completion response cannot be unserialised.');
    }

    /**
     * A redirect to the location, with a `302` or a `303`.
     *
     * @param  int  $status
     * @param  string  $location
     * @param  string  $body
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function redirect(int $status, #[\SensitiveParameter] string $location, string $body): self
    {
        if ($status !== self::FOUND && $status !== self::SEE_OTHER) {
            throw new \InvalidArgumentException('A completion redirects with a 302 or a 303, never another status.');
        }

        return new self($status, self::HEADERS, $body, $location);
    }

    /**
     * A `400` with no redirect, for a completion with no trusted redirect
     * target.
     *
     * @param  string  $body
     * @return self
     */
    public static function rejected(string $body): self
    {
        return new self(self::BAD_REQUEST, self::HEADERS, $body);
    }

    /**
     * A `429` with no redirect, to be tried again after the seconds given.
     *
     * @param  int  $retryAfter
     * @param  string  $body
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function rateLimited(int $retryAfter, string $body): self
    {
        if ($retryAfter < 1) {
            throw new \InvalidArgumentException('A rate limited completion waits at least one second.');
        }

        return new self(self::TOO_MANY_REQUESTS, [...self::HEADERS, 'Retry-After' => (string) $retryAfter], $body);
    }

    /**
     * The `Location` of a redirect, carrying the handoff code of a completed
     * one, or null for a refusal.
     *
     * @return ?string
     */
    public function location(): ?string
    {
        /** @var ?string */
        return $this->location->getValue();
    }

    /**
     * What `json_encode()` writes: the `Location` with the handoff code
     * redacted.
     *
     * @return array{status: int, headers: array<string, string>, location: ?string, body: string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'status'   => $this->status,
            'headers'  => $this->headers,
            'location' => $this->shownLocation(),
            'body'     => $this->body,
        ];
    }

    /**
     * The HTTP response: the status, the headers, the `Location` of a redirect
     * and the body, and nothing else.
     *
     * Symfony adds a `Date` header, and writes `Cache-Control: no-store` as
     * `no-store, private`, which only narrows it further.
     *
     * @param  mixed  $request
     * @return \Illuminate\Http\Response
     */
    #[\Override]
    public function toResponse(mixed $request): Response
    {
        $location = $this->location();
        $headers  = $location === null ? $this->headers : [...$this->headers, 'Location' => $location];

        return new Response($this->body, $this->status, $headers);
    }

    /**
     * The `Location` as a dump shows it: the value of every `code` parameter,
     * in the query or the fragment, redacted.
     *
     * @return ?string
     */
    private function shownLocation(): ?string
    {
        $location = $this->location();

        return $location === null ? null : preg_replace(self::CODE_VALUE, self::REDACTED, $location) ?? self::REDACTED;
    }
}
