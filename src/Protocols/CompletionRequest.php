<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use Illuminate\Http\Request;

/**
 * What arrived at a connection's assertion consumer service or callback
 * (SSO-5.3, SSO-5.4, SSO-7.1): the HTTP method, the raw query string (so a
 * repeated or conflicting parameter can be refused, which a parsed query would
 * hide) and the posted form fields.
 *
 * It carries an assertion or an authorisation code, so it never reaches a log,
 * an exception, a queue or an event (SSO-9.8, SSO-11.9): a dump shows only the
 * method and the names of what it holds, and it refuses to be serialised.
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
     * Constructor.
     *
     * The query string and the posted fields are held in
     * `\SensitiveParameterValue`, so no dump (PHP's own, or the one behind
     * Laravel's `dump()`, which also lists private properties), export, array
     * cast or JSON encoding shows them.
     *
     * @param  string  $method
     * @param  string  $query
     * @param  array<array-key, mixed>  $body
     */
    public function __construct(

        /** The HTTP method, in upper case. */
        public string $method,

        // The raw query string, without the `?`; held wrapped.
        #[\SensitiveParameter]
        string $query,

        // The posted form fields, as parsed; held wrapped.
        #[\SensitiveParameter]
        array $body,
    ) {
        $this->query  = new \SensitiveParameterValue($query);
        $this->body   = new \SensitiveParameterValue($body);
        $this->fields = array_keys($body);
    }

    /**
     * What a dump shows: the method and the names of the posted fields, never a
     * value.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['method' => $this->method, 'query' => '[redacted]', 'body' => $this->fields];
    }

    /**
     * Refuse to be serialised: a response is validated in the request it
     * arrived in and kept nowhere.
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
     * What JSON encoding shows: the same as a dump, never a value.
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
