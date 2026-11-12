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
 * The RFC 7591 client metadata an administrator registers at the provider, and
 * the public JWKS the application serves. Incomplete connections are described.
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
     * Describe the relying party side, naming the public JWKS URL for
     * `private_key_jwt` so a rotation needs no re-registration.
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
     * Describe the relying party side with the public keys inline; these must
     * be registered again whenever a key is added or made current.
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
     * The body of the public JWKS URL; the package adds no route for it.
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
     * The client metadata, with the closure's key members under
     * `private_key_jwt`, or why it cannot be described.
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
     * The client metadata with the signing algorithm and key members, or why
     * the keys cannot be registered.
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
     * The current then next client assertion keys, read together from one state
     * of the ring.
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
     * Why the published keys cannot be registered or served, or `null`.
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
     * The public JWK of each published key, under the algorithm it signs with.
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
     * Encode the document as JSON of the media type.
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
