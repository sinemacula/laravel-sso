<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use Carbon\CarbonImmutable;

/**
 * A single-use key the completion records against replay, held until the last
 * moment the response could still be accepted.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ReplayRecord
{
    /** @var string The single-use namespace a SAML assertion id is recorded in. */
    public const string SAML_ASSERTION = 'saml_assertion';

    /** @var string The version of the key's encoding. */
    private const string VERSION = 'v1';

    /** @var \SensitiveParameterValue The key, in its namespace. */
    private \SensitiveParameterValue $key;

    /**
     * Constructor.
     *
     * @param  string  $namespace
     * @param  string  $key
     * @param  \Carbon\CarbonImmutable  $until
     */
    private function __construct(

        /** The single-use namespace the key is recorded in. */
        public string $namespace,

        // Held wrapped, so not promoted
        #[\SensitiveParameter]
        string $key,

        /** The latest moment the response could still be accepted. */
        public CarbonImmutable $until,
    ) {
        $this->key = new \SensitiveParameterValue($key);
    }

    /**
     * Show the namespace and expiry, never the key.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['namespace' => $this->namespace, 'key' => '[redacted]', 'until' => $this->until->toIso8601String()];
    }

    /**
     * Refuse to be serialised: the record lives only for its completion.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A replay record cannot be serialised.');
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
        throw new \LogicException('A replay record cannot be unserialised.');
    }

    /**
     * A SAML assertion id, scoped by connection and issuer so one tenant's
     * identity provider cannot poison another's.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $assertionId
     * @param  \Carbon\CarbonImmutable  $until
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function samlAssertion(string $connectionId, string $issuer, string $assertionId, CarbonImmutable $until): self
    {
        if ($connectionId === '' || $issuer === '' || $assertionId === '') {
            throw new \InvalidArgumentException('An assertion is recorded by a non-empty connection, issuer and id.');
        }

        return new self(self::SAML_ASSERTION, self::encode([$connectionId, $issuer, $assertionId]), $until);
    }

    /**
     * The key, for the single-use store.
     *
     * @return string
     */
    public function key(): string
    {
        /** @var string */
        return $this->key->getValue();
    }

    /**
     * Versioned, length-prefixed encoding, so no two tuples share a key.
     *
     * @param  list<string>  $parts
     * @return string
     */
    private static function encode(array $parts): string
    {
        return self::VERSION . implode('', array_map(static fn (string $part): string => '|' . strlen($part) . ':' . $part, $parts));
    }
}
