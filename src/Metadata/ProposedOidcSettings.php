<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;

/**
 * The settings an import of an OpenID provider's discovery document proposes
 * for a connection (SSO-2.8), for an administrator to review: nothing in it is
 * written or trusted until it is saved through
 * `Connections\ConnectionService::update()`, with freshness.
 *
 * - `settings()`: `issuer`, `authorization_endpoint`, `token_endpoint`,
 *   `jwks_uri`, `userinfo_endpoint` when the document names one, `returns_iss`
 *   and `id_token_algorithms`, as the connection's settings name them, ready to
 *   give `update()`;
 * - `authMethods()`: the client authentication methods the document lists, for
 *   choosing the connection's `client_authentication`, which the import never
 *   proposes;
 * - `keys()`: each admitted key's `kid`, `kty` and `alg`, for review. No other
 *   member of a key is held, and no secret: the keys themselves are stored by
 *   the first refresh or refetch, never by a save.
 *
 * Everything in it came from whoever serves the issuer's URL, so it is held in
 * a `\SensitiveParameterValue`: a dump and `json_encode()` show the names and
 * how many of each, never a value, and it refuses to be serialised or
 * unserialised.
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
 *     keys: list<array{kid: ?string, kty: string, alg: ?string}>
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
     * What a dump shows: the names of the settings and how many client
     * authentication methods and keys it holds, never a value.
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
     * @return self
     *
     * @throws \LogicException
     */
    public static function of(DiscoveryDocument $document, ProviderKeySet $keys): self
    {
        return new self([
            'settings'     => $document->settings(),
            'auth_methods' => $document->authMethods(),
            'keys'         => array_map(static fn (ProviderKey $key): array => self::reviewOf($key), $keys->keys),
        ]);
    }

    /**
     * The settings proposed, ready to give `ConnectionService::update()`.
     *
     * @return DiscoverySettings
     */
    public function settings(): array
    {
        return $this->all()['settings'];
    }

    /**
     * The client authentication methods the document lists; none when it lists
     * none.
     *
     * @return list<string>
     */
    public function authMethods(): array
    {
        return $this->all()['auth_methods'];
    }

    /**
     * Each admitted key's `kid`, `kty` and `alg`, in the order the JWKS gave
     * them, `null` for a member the key does not have.
     *
     * @return list<ProposedKey>
     */
    public function keys(): array
    {
        return $this->all()['keys'];
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
