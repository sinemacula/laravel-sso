<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use Carbon\CarbonImmutable;

/**
 * What a protocol driver asks the completion to record once, against replay,
 * after it validated a response (SSO-6.6, SSO-11.5): a key in a namespace of
 * the single-use store, until the latest moment any acceptance rule would still
 * accept the response.
 *
 * A SAML assertion's key is its id, scoped by the connection and the issuer so
 * one tenant's identity provider cannot poison another's: a versioned,
 * length-prefixed encoding of the three, so no choice of values makes two
 * different tuples share a key. Its expiry is the actual last acceptance
 * moment: the earliest of each `NotOnOrAfter` and the `IssueInstant` maximum
 * age, each with the clock skew.
 *
 * The completion records it in its locked transaction, after the driver's
 * validation and before any downstream effect, so an invalid response records
 * nothing; a key already held refuses the completion with `replayed`. The key
 * holds what the response carried, so a dump shows only its namespace and
 * expiry, and it refuses to be serialised.
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

        // The key; held wrapped
        #[\SensitiveParameter]
        string $key,

        /** The latest moment the response could still be accepted. */
        public CarbonImmutable $until,
    ) {
        $this->key = new \SensitiveParameterValue($key);
    }

    /**
     * What a dump shows: the namespace and the expiry, never the key.
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
     * A SAML assertion's id, scoped by the connection and the issuer, until the
     * moment given.
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
     * The versioned, length-prefixed encoding of the parts: the version, then
     * each part as its length in bytes, a colon and the part itself.
     *
     * @param  list<string>  $parts
     * @return string
     */
    private static function encode(array $parts): string
    {
        return self::VERSION . implode('', array_map(static fn (string $part): string => '|' . strlen($part) . ':' . $part, $parts));
    }
}
