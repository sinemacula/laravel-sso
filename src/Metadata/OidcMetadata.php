<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;

/**
 * The discovery document and JWKS one fetch of an OpenID provider gave.
 *
 * Its values are untrusted, so a dump shows none and it refuses to be
 * serialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OidcMetadata implements \JsonSerializable
{
    /** @var \SensitiveParameterValue The discovery document. */
    private \SensitiveParameterValue $document;

    /** @var \SensitiveParameterValue The keys the JWKS gave. */
    private \SensitiveParameterValue $keys;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\DiscoveryDocument  $document
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet  $keys
     * @param  \Carbon\CarbonImmutable  $keysValidatedAt
     */
    public function __construct(

        // The discovery document; held wrapped
        DiscoveryDocument $document,

        // The keys the JWKS gave; held wrapped
        ProviderKeySet $keys,

        /** The moment the JWKS was validated. */
        public CarbonImmutable $keysValidatedAt,
    ) {
        $this->document = new \SensitiveParameterValue($document);
        $this->keys     = new \SensitiveParameterValue($keys);
    }

    /**
     * What a dump shows: how many keys it holds and when they were validated,
     * never a value.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'document'          => '[redacted]',
            'keys'              => count($this->keys()->keys),
            'keys_validated_at' => $this->keysValidatedAt->toIso8601String(),
        ];
    }

    /**
     * Refuse to be serialised: it lives only for its import or refresh.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('OIDC metadata cannot be serialised.');
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
        throw new \LogicException('OIDC metadata cannot be unserialised.');
    }

    /**
     * The discovery document.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\DiscoveryDocument
     */
    public function document(): DiscoveryDocument
    {
        /** @var \SineMacula\Laravel\Sso\Metadata\DiscoveryDocument */
        return $this->document->getValue();
    }

    /**
     * The keys the JWKS gave.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet
     */
    public function keys(): ProviderKeySet
    {
        /** @var \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet */
        return $this->keys->getValue();
    }

    /**
     * What `json_encode()` writes: what a dump shows.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
