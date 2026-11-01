<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

/**
 * A SAML `AuthnRequest` as the SAML adapter wrote it for its binding (SSO-5.3,
 * SAML 2.0 Bindings §3.4 and §3.5): its `ID`, the binding it is sent by, and
 * the transport fields in the order the binding sends them, `SAMLRequest` and
 * `RelayState`, then `SigAlg` and `Signature` for a signed HTTP-Redirect.
 *
 * The fields carry the encoded message and the flow's `RelayState`, so they
 * live in one `\SensitiveParameterValue` and leave the value only through
 * `fields()` and `query()`, which the navigation is built from: a dump, by
 * PHP's own functions or by the VarDumper behind Laravel's helpers (which also
 * lists private properties), and `json_encode()` show the field names with
 * every value `[redacted]`, and the value refuses to be serialised or
 * unserialised, so it never reaches a queue, a cache, a log or an event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OutgoingRequest implements \JsonSerializable
{
    /** @var string The HTTP-Redirect binding: the message deflated into the query string. */
    public const string HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

    /** @var string The HTTP-POST binding: the message posted from a form. */
    public const string HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    /** @var string What a dump shows for each field's value. */
    private const string REDACTED = '[redacted]';

    /** @var \SensitiveParameterValue The transport fields, by name, in the order they are sent. */
    private \SensitiveParameterValue $fields;

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $binding
     * @param  array<string, string>  $fields
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The request's `ID`, which the response's `InResponseTo` must equal. */
        public string $id,

        /** The binding it is sent by: `HTTP_REDIRECT` or `HTTP_POST`. */
        public string $binding,

        // The transport fields, by name, in sending order; held wrapped
        #[\SensitiveParameter]
        array $fields,
    ) {
        if ($binding !== self::HTTP_REDIRECT && $binding !== self::HTTP_POST) {
            throw new \InvalidArgumentException('An AuthnRequest is sent by the HTTP-Redirect or the HTTP-POST binding.');
        }

        $this->fields = new \SensitiveParameterValue($fields);
    }

    /**
     * What a dump shows: the id, the binding and the names of the fields, never
     * their values.
     *
     * @return array{id: string, binding: string, fields: array<string, string>}
     */
    public function __debugInfo(): array
    {
        return [
            'id'      => $this->id,
            'binding' => $this->binding,
            'fields'  => array_fill_keys(array_keys($this->fields()), self::REDACTED),
        ];
    }

    /**
     * Refuse to be serialised: the request lives only for the start that wrote
     * it.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException(sprintf('A %s cannot be serialised.', self::class));
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
        throw new \LogicException(sprintf('A %s cannot be unserialised.', self::class));
    }

    /**
     * The query string of the fields: each name, `=` and its value
     * percent-encoded (RFC 3986), joined by `&`, in the order given. An
     * HTTP-Redirect signature is over exactly these bytes, for the fields
     * before `Signature`.
     *
     * @param  array<string, string>  $fields
     * @return string
     */
    public static function encode(#[\SensitiveParameter] array $fields): string
    {
        $pairs = [];

        foreach ($fields as $name => $value) {
            $pairs[] = $name . '=' . rawurlencode($value);
        }

        return implode('&', $pairs);
    }

    /**
     * Whether the request is sent by the HTTP-Redirect binding.
     *
     * @return bool
     */
    public function isRedirect(): bool
    {
        return $this->binding === self::HTTP_REDIRECT;
    }

    /**
     * The transport fields, by name, whole, in the order they are sent.
     *
     * @return array<string, string>
     */
    public function fields(): array
    {
        /** @var array<string, string> */
        return $this->fields->getValue();
    }

    /**
     * The fields as the HTTP-Redirect query string, whole.
     *
     * @return string
     */
    public function query(): string
    {
        return self::encode($this->fields());
    }

    /**
     * What `json_encode()` writes: never a field's value.
     *
     * @return array{id: string, binding: string, fields: array<string, string>}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
