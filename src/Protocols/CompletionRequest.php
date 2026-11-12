<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use Illuminate\Http\Request;

/**
 * What arrived at a connection's ACS or callback. The raw query is kept so a
 * repeated parameter can be refused; dumps redact it and serialising throws.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CompletionRequest implements \JsonSerializable
{
    /** @var \SensitiveParameterValue The raw query string, without the `?`. */
    private \SensitiveParameterValue $query;

    /** @var \SensitiveParameterValue The posted form fields, as parsed. */
    private \SensitiveParameterValue $body;

    /** @var list<array-key> The names of the posted form fields. */
    private array $fields;

    /**
     * Wraps the query and fields so no dump, export or array cast shows them.
     *
     * @param  string  $method
     * @param  string  $query
     * @param  array<array-key, mixed>  $body
     */
    public function __construct(

        /** The HTTP method, in upper case. */
        public string $method,

        // Held wrapped, so not promoted.
        #[\SensitiveParameter]
        string $query,

        // Held wrapped, so not promoted.
        #[\SensitiveParameter]
        array $body,
    ) {
        $this->query  = new \SensitiveParameterValue($query);
        $this->body   = new \SensitiveParameterValue($body);
        $this->fields = array_keys($body);
    }

    /**
     * Show the method and field names, never a value.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['method' => $this->method, 'query' => '[redacted]', 'body' => $this->fields];
    }

    /**
     * Refuse to be serialised; a response is validated in its own request.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A completion request cannot be serialised.');
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
        throw new \LogicException('A completion request cannot be unserialised.');
    }

    /**
     * Encode the same redacted view as a dump.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * The raw query string, without the `?`.
     *
     * @return string
     */
    public function query(): string
    {
        /** @var string */
        return $this->query->getValue();
    }

    /**
     * The posted form fields, as parsed.
     *
     * @return array<array-key, mixed>
     */
    public function body(): array
    {
        /** @var array<array-key, mixed> */
        return $this->body->getValue();
    }

    /**
     * What the request being served carries.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public static function fromRequest(Request $request): self
    {
        $query = $request->server('QUERY_STRING');

        return new self($request->getMethod(), is_string($query) ? $query : '', $request->request->all());
    }
}
