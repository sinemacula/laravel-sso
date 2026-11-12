<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;

/**
 * The settings an import of an OpenID provider's discovery document proposes,
 * trusted only once saved through `Connections\ImportSaver::save()`.
 *
 * Its values are untrusted, so a dump shows names and counts alone and it
 * refuses to be serialised.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-import-type DiscoverySettings from \SineMacula\Laravel\Sso\Metadata\DiscoveryDocument
 *
 * @phpstan-type ProposedKey array{kid: ?string, kty: string, alg: ?string}
 * @phpstan-type OidcProposal array{
 *     settings: array{
 *         issuer: string,
 *         authorization_endpoint: string,
 *         token_endpoint: string,
 *         jwks_uri: string,
 *         userinfo_endpoint?: string,
 *         returns_iss: bool,
 *         id_token_algorithms: list<string>
 *     },
 *     auth_methods: list<string>,
 *     keys: list<array{kid: ?string, kty: string, alg: ?string}>,
 *     validated_at: \Carbon\CarbonImmutable
 * }
 */
final readonly class ProposedOidcSettings implements \JsonSerializable
{
    /** @var \SensitiveParameterValue What the document proposes, by name. */
    private \SensitiveParameterValue $values;

    /**
     * Constructor.
     *
     * @param  OidcProposal  $values
     */
    private function __construct(

        // What the document proposes, by name; held wrapped
        #[\SensitiveParameter]
        array $values,
    ) {
        $this->values = new \SensitiveParameterValue($values);
    }

    /**
     * What a dump shows: the setting names and how many methods and keys, never
     * a value.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'settings'     => array_keys($this->settings()),
            'auth_methods' => count($this->authMethods()),
            'keys'         => count($this->keys()),
        ];
    }

    /**
     * Refuse to be serialised: what the document proposes lives only for the
     * administrator's review.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('Proposed settings cannot be serialised.');
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
        throw new \LogicException('Proposed settings cannot be unserialised.');
    }

    /**
     * What the read document and the keys its JWKS gave propose.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\DiscoveryDocument  $document
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet  $keys
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @return self
     *
     * @throws \LogicException
     */
    public static function of(DiscoveryDocument $document, ProviderKeySet $keys, CarbonImmutable $validatedAt): self
    {
        return new self([
            'settings'     => $document->settings(),
            'auth_methods' => $document->authMethods(),
            'keys'         => array_map(static fn (ProviderKey $key): array => self::reviewOf($key), $keys->keys),
            'validated_at' => $validatedAt,
        ]);
    }

    /**
     * The settings proposed, ready to give `ImportSaver::save()`.
     *
     * @return DiscoverySettings
     */
    public function settings(): array
    {
        return $this->all()['settings'];
    }

    /**
     * The client authentication methods the document lists, for choosing
     * `client_authentication`, which the import never proposes.
     *
     * @return list<string>
     */
    public function authMethods(): array
    {
        return $this->all()['auth_methods'];
    }

    /**
     * Each admitted key's `kid`, `kty` and `alg`, for review; a save never
     * stores the keys themselves.
     *
     * @return list<ProposedKey>
     */
    public function keys(): array
    {
        return $this->all()['keys'];
    }

    /**
     * The fetch the document came from.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\ValidatedFetch
     */
    public function fetch(): ValidatedFetch
    {
        return new ValidatedFetch($this->all()['validated_at']);
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

    /**
     * Everything proposed, by name.
     *
     * @return OidcProposal
     */
    private function all(): array
    {
        /** @var OidcProposal */
        return $this->values->getValue();
    }

    /**
     * What an administrator reviews of a key.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey  $key
     * @return ProposedKey
     */
    private static function reviewOf(ProviderKey $key): array
    {
        $algorithm = $key->toArray()['alg'] ?? null;

        return ['kid' => $key->keyId(), 'kty' => $key->keyType(), 'alg' => is_string($algorithm) ? $algorithm : null];
    }
}
