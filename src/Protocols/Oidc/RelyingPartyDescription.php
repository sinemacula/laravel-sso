<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ClientKey;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;

/**
 * Describes what an administrator registers at the OpenID provider for a
 * connection (SSO-5.9), as a JSON object shaped as RFC 7591 client metadata, in
 * this order:
 *
 * - `redirect_uris`: the callback `Contracts\EndpointResolver` builds
 *   (SSO-5.5), never one read from the request;
 * - `response_types` and `grant_types`: the authorisation code flow, the only
 *   one the package runs (SSO-5.4);
 * - `token_endpoint_auth_method`: the connection's client authentication;
 * - with `private_key_jwt` only, `token_endpoint_auth_signing_alg` (the
 *   algorithm of the key that signs, the current one when there is one) and
 *   `jwks`, the public JWK of each published `client_assertion` key
 *   (`Keys\KeyRing::published()`), the current one and then the next (SSO-2.7),
 *   each under the `kid` its private half signs with (`Jose\ClientKey`).
 *
 * It never holds a client secret, a private member, the client id, or a key id
 * other than the thumbprint. The body is the same for the same connection, keys
 * and endpoints.
 *
 * A connection is described whatever it holds, enabled or not, complete or not,
 * so an administrator can register it first. `private_key_jwt` with no current
 * or next key has nothing to register, and is `connection_unavailable`. An
 * endpoint configuration that cannot build the callback, and a published key
 * the package would not sign with, fail closed with an
 * `InvalidArgumentException`.
 *
 * It changes nothing, reports no event, and holds nothing of one call for the
 * next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RelyingPartyDescription
{
    /** @var string The description's media type. */
    private const string CONTENT_TYPE = 'application/json';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\EndpointResolver  $endpoints
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     */
    public function __construct(

        /** The connection's callback. */
        private EndpointResolver $endpoints,

        /** The connection's published client assertion keys. */
        private KeyRing $keys,
    ) {}

    /**
     * Describe the connection's relying party side.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function describe(SsoConnection $connection, OidcOptions $options): ServiceProviderDescription
    {
        $method   = $options->clientAuthentication();
        $metadata = [
            'redirect_uris'              => [$this->endpoints->endpoints($connection)->callback],
            'response_types'             => ['code'],
            'grant_types'                => ['authorization_code'],
            'token_endpoint_auth_method' => $method,
        ];

        if ($method !== CredentialKind::PRIVATE_KEY_JWT->value) {
            return self::document($metadata);
        }

        $jwks = $this->publishedJwks($connection);

        if ($jwks === []) {
            return ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE);
        }

        return self::document([...$metadata, 'token_endpoint_auth_signing_alg' => $jwks[0]['alg'], 'jwks' => ['keys' => $jwks]]);
    }

    /**
     * The public JWK of each published client assertion key, the current one
     * and then the next, read together so they are of one state of the ring.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return list<array<string, string>>
     *
     * @throws \InvalidArgumentException
     */
    private function publishedJwks(SsoConnection $connection): array
    {
        $published = $this->keys->published($connection->getConnectionId(), KeyUse::CLIENT_ASSERTION);

        return array_map(static fn (KeySummary $key): array => ClientKey::publicJwk((string) $key->key->publicKey), $published);
    }

    /**
     * The client metadata as the description's document.
     *
     * @param  array<string, mixed>  $metadata
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private static function document(array $metadata): ServiceProviderDescription
    {
        return ServiceProviderDescription::document(self::CONTENT_TYPE, json_encode($metadata, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }
}
