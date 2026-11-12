<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

/**
 * A written `AuthnRequest` and its transport fields. The fields carry the
 * `RelayState`, so dumps and JSON redact them and serialising throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OutgoingRequest implements \JsonSerializable
{
    /** @var string The HTTP-Redirect binding. */
    public const string HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

    /** @var string The HTTP-POST binding. */
    public const string HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    /** @var \SensitiveParameterValue The transport fields, by name, in sending order. */
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

        // Held wrapped, so not promoted
        #[\SensitiveParameter]
        array $fields,
    ) {
        if ($binding !== self::HTTP_REDIRECT && $binding !== self::HTTP_POST) {
            throw new \InvalidArgumentException('An AuthnRequest is sent by the HTTP-Redirect or the HTTP-POST binding.');
        }

        $this->fields = new \SensitiveParameterValue($fields);
    }

    /**
     * Show the id, the binding and the field names, never a value.
     *
     * @return array{id: string, binding: string, fields: array<string, string>}
     */
    public function __debugInfo(): array
    {
        return [
            'id'      => $this->id,
            'binding' => $this->binding,
            'fields'  => array_fill_keys(array_keys($this->fields()), '[redacted]'),
        ];
    }

    /**
     * Refuse to be serialised; the request lives only for its start.
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
     * The fields as an RFC 3986 query string, in order; an HTTP-Redirect
     * signature covers exactly these bytes.
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
     * The transport fields, unredacted, in sending order.
     *
     * @return array<string, string>
     */
    public function fields(): array
    {
        /** @var array<string, string> */
        return $this->fields->getValue();
    }

    /**
     * The fields as the HTTP-Redirect query string, unredacted.
     *
     * @return string
     */
    public function query(): string
    {
        return self::encode($this->fields());
    }

    /**
     * Encode the same redacted view as a dump.
     *
     * @return array{id: string, binding: string, fields: array<string, string>}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
