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
 * - with `private_key_jwt` only, `token_endpoint_auth_signing_alg` (the pinned
 *   algorithm, or the default of the key that signs, the current one when there
 *   is one) and exactly one of:
 *   - `jwks_uri` (`describe()`, preferred): the public JWKS URL the resolver
 *     builds and the application serves, so a rotation needs no
 *     re-registration;
 *   - `jwks` (`describeWithInlineKeys()`): the public JWK of each published
 *     `client_assertion` key, for a provider that requires uploaded keys, which
 *     must be registered again whenever a next key is added or made current.
 *
 * `publicKeys()` is the body of that URL: `{"keys": [...]}`, the public JWK of
 * each published `client_assertion` key (`Keys\KeyRing::published()`), the
 * current one and then the next (SSO-2.7), each under the `kid` its private
 * half signs with (`Jose\ClientKey`) and the `alg` it signs under, as
 * `application/jwk-set+json`. The package adds no route for it: the application
 * serves the body it answers.
 *
 * Nothing here holds a client secret, a private member, the client id, or a key
 * id other than the thumbprint. Each body is the same for the same connection,
 * keys and endpoints.
 *
 * A connection is described whatever it holds, enabled or not, complete or not,
 * so an administrator can register it first, but what it does hold must be
 * valid: a client authentication the package does not support, a pinned
 * algorithm that is not one it signs with, or one a published key cannot sign
 * under, is `settings_invalid`, in every document. `private_key_jwt` with no
 * current or next key has nothing to register or serve, and is
 * `connection_unavailable`, as is the public JWKS of a client secret
 * connection. An endpoint configuration that cannot build the URLs, and a
 * published key the package would not sign with, fail closed with an
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

    /** @var string The media type of the public JWKS. */
    private const string JWKS_CONTENT_TYPE = 'application/jwk-set+json';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\EndpointResolver  $endpoints
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     */
    public function __construct(

        /** The connection's callback and public JWKS URL. */
        private EndpointResolver $endpoints,

        /** The connection's published client assertion keys. */
        private KeyRing $keys,
    ) {}

    /**
     * Describe the connection's relying party side, naming the public JWKS URL
     * for `private_key_jwt`.
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
        return $this->described($connection, $options, fn (array $jwks): array => ['jwks_uri' => $this->endpoints->endpoints($connection)->jwks]);
    }

    /**
     * Describe the connection's relying party side with the public keys in the
     * document, for a provider that requires uploaded keys.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function describeWithInlineKeys(SsoConnection $connection, OidcOptions $options): ServiceProviderDescription
    {
        return $this->described($connection, $options, static fn (array $jwks): array => ['jwks' => ['keys' => $jwks]]);
    }

    /**
     * The body of the connection's public JWKS URL.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function publicKeys(SsoConnection $connection, OidcOptions $options): ServiceProviderDescription
    {
        $method = $options->clientAuthentication();

        if ($method !== CredentialKind::PRIVATE_KEY_JWT->value) {
            $supported = in_array($method, OidcSettings::CLIENT_AUTHENTICATIONS, true);

            return ServiceProviderDescription::unavailable($supported ? FailureReason::CONNECTION_UNAVAILABLE : FailureReason::SETTINGS_INVALID);
        }

        $published = $this->published($connection);
        $refusal   = self::keysRefusal($published, $options);

        return $refusal === null ? self::document(self::JWKS_CONTENT_TYPE, ['keys' => self::jwks($published, $options)]) : ServiceProviderDescription::unavailable($refusal);
    }

    /**
     * The client metadata, with what the closure gives for the published keys
     * under `private_key_jwt`; or why the connection cannot be described.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \Closure(list<array<string, string>>): array<string, mixed>  $keys
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function described(SsoConnection $connection, OidcOptions $options, \Closure $keys): ServiceProviderDescription
    {
        $method = $options->clientAuthentication();

        if (!in_array($method, OidcSettings::CLIENT_AUTHENTICATIONS, true)) {
            return ServiceProviderDescription::unavailable(FailureReason::SETTINGS_INVALID);
        }

        $metadata = [
            'redirect_uris'              => [$this->endpoints->endpoints($connection)->callback],
            'response_types'             => ['code'],
            'grant_types'                => ['authorization_code'],
            'token_endpoint_auth_method' => $method,
        ];

        return $method === CredentialKind::PRIVATE_KEY_JWT->value ? $this->keyed($connection, $options, $metadata, $keys) : self::document(self::CONTENT_TYPE, $metadata);
    }

    /**
     * The client metadata with the signing algorithm and what the closure gives
     * for the published keys; or why they cannot be registered.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  array<string, mixed>  $metadata
     * @param  \Closure(list<array<string, string>>): array<string, mixed>  $keys
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function keyed(SsoConnection $connection, OidcOptions $options, array $metadata, \Closure $keys): ServiceProviderDescription
    {
        $published = $this->published($connection);
        $refusal   = self::keysRefusal($published, $options);

        if ($refusal !== null) {
            return ServiceProviderDescription::unavailable($refusal);
        }

        $jwks = self::jwks($published, $options);

        return self::document(self::CONTENT_TYPE, [...$metadata, 'token_endpoint_auth_signing_alg' => $jwks[0]['alg'], ...$keys($jwks)]);
    }

    /**
     * The connection's published client assertion keys, the current one and
     * then the next, read together so they are of one state of the ring.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return list<\SineMacula\Laravel\Sso\Keys\KeySummary>
     *
     * @throws \InvalidArgumentException
     */
    private function published(SsoConnection $connection): array
    {
        return $this->keys->published($connection->getConnectionId(), KeyUse::CLIENT_ASSERTION);
    }

    /**
     * Why the published keys cannot be registered or served, or `null`: a
     * pinned algorithm the package does not sign with or one of them cannot
     * sign under, or no key at all.
     *
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $published
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function keysRefusal(array $published, OidcOptions $options): ?FailureReason
    {
        $pinned = $options->clientAssertionAlgorithm();
        $fits   = static fn (KeySummary $key): bool => ClientAssertionAlgorithm::fits($pinned, $key->type);
        $known  = $pinned === null || in_array($pinned, OidcSettings::CLIENT_ASSERTION_ALGORITHMS, true);

        return match (true) {
            !$known || array_filter($published, $fits) !== $published => FailureReason::SETTINGS_INVALID,
            $published === []                                         => FailureReason::CONNECTION_UNAVAILABLE,
            default                                                   => null,
        };
    }

    /**
     * The public JWK of each published key, each under the algorithm it signs
     * with.
     *
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $published
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @return list<array<string, string>>
     *
     * @throws \InvalidArgumentException
     */
    private static function jwks(array $published, OidcOptions $options): array
    {
        $pinned = $options->clientAssertionAlgorithm();

        return array_map(static fn (KeySummary $key): array => ClientKey::publicJwk((string) $key->key->publicKey, $pinned), $published);
    }

    /**
     * The JSON document of the media type.
     *
     * @param  string  $contentType
     * @param  array<string, mixed>  $document
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private static function document(string $contentType, array $document): ServiceProviderDescription
    {
        return ServiceProviderDescription::document($contentType, json_encode($document, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }
}
