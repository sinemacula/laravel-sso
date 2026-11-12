<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use Random\RandomException;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\JoseAdapter;

/**
 * Sends the token request of an OpenID Connect completion, once and with no
 * retry, outside any storage transaction so a provider call never holds a lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TokenExchange
{
    /** @var string The grant the token request makes. */
    private const string GRANT_TYPE = 'authorization_code';

    /** @var string The message for a token request inside a storage transaction. */
    private const string INSIDE_TRANSACTION = 'A token request is sent outside any transaction on the package\'s storage connection: a provider call never holds a lock.';

    /** @var string The message for a request with no PKCE verifier. */
    private const string NO_VERIFIER = 'An OpenID Connect authorisation request keeps its PKCE verifier.';

    /** @var string The message for a client assertion with no randomness for its `jti`. */
    private const string NO_RANDOMNESS = 'The system could not supply the randomness a client assertion needs.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Fetcher  $fetcher
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionSecrets  $secrets
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\JoseAdapter  $jose
     * @param  \SineMacula\Laravel\Sso\Contracts\EndpointResolver  $endpoints
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits  $limits
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** Sends the one attempt. */
        private Fetcher $fetcher,

        /** The connection's client secret. */
        private ConnectionSecrets $secrets,

        /** The connection's client assertion key. */
        private KeyRing $keys,

        /** Signs a client assertion. */
        private JoseAdapter $jose,

        /** The connection's callback. */
        private EndpointResolver $endpoints,

        /** The request's timeout and size cap. */
        private OidcLimits $limits,

        /** The client assertion's `iat`. */
        private Clock $clock,
    ) {}

    /**
     * The connection's client authentication for one attempt, or `null` when it
     * holds no secret or key for it.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @return ?\SineMacula\Laravel\Sso\Fetching\FetchCredentials
     *
     * @throws \LogicException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \RuntimeException
     */
    public function credentials(SsoConnection $connection, OidcOptions $options): ?FetchCredentials
    {
        return match ($options->clientAuthentication()) {
            CredentialKind::CLIENT_SECRET_BASIC->value => $this->secret($connection, $options, CredentialKind::CLIENT_SECRET_BASIC),
            CredentialKind::CLIENT_SECRET_POST->value  => $this->secret($connection, $options, CredentialKind::CLIENT_SECRET_POST),
            CredentialKind::PRIVATE_KEY_JWT->value     => $this->assertion($connection, $options),
            default                                    => null,
        };
    }

    /**
     * Send the token request once; a timeout leaves the request consumed, since
     * the code may have been spent.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  string  $code
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchCredentials  $credentials
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     *
     * @throws \LogicException
     */
    public function send(
        SsoConnection $connection,
        OidcOptions $options,
        #[\SensitiveParameter] string $code,
        ConsumedRequest $consumed,
        FetchCredentials $credentials,
    ): FetchResult {
        StorageConnection::assertNoTransaction(self::INSIDE_TRANSACTION);

        $verifier = $consumed->codeVerifier() ?? throw new \LogicException(self::NO_VERIFIER);
        $form     = [
            'grant_type'    => self::GRANT_TYPE,
            'code'          => $code,
            'redirect_uri'  => $this->endpoints->endpoints($connection)->callback,
            'code_verifier' => $verifier->reveal(),
        ];

        return $this->fetcher->fetch(FetchRequest::token(
            $options->tokenEndpoint(),
            $form,
            $credentials,
            $this->limits->tokenTimeoutSeconds(),
            $this->limits->maxTokenResponseBytes(),
        ));
    }

    /**
     * The failure of a client assertion the system had no randomness for.
     *
     * @return \RuntimeException
     */
    private static function noRandomness(): \RuntimeException
    {
        return new \RuntimeException(self::NO_RANDOMNESS);
    }

    /**
     * The client secret, as the kind carries it.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind  $kind
     * @return ?\SineMacula\Laravel\Sso\Fetching\FetchCredentials
     *
     * @throws \LogicException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \RuntimeException
     */
    private function secret(SsoConnection $connection, OidcOptions $options, CredentialKind $kind): ?FetchCredentials
    {
        $secret = $this->secrets->revealFor($connection, OidcSetting::CLIENT_SECRET->value);

        if ($secret === null) {
            return null;
        }

        return $kind === CredentialKind::CLIENT_SECRET_POST
            ? FetchCredentials::clientSecretPost($options->clientId(), $secret->reveal())
            : FetchCredentials::clientSecretBasic($options->clientId(), $secret->reveal());
    }

    /**
     * A fresh client assertion signed by the connection's current key.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @return ?\SineMacula\Laravel\Sso\Fetching\FetchCredentials
     *
     * @throws \RuntimeException
     */
    private function assertion(SsoConnection $connection, OidcOptions $options): ?FetchCredentials
    {
        $connectionId = $connection->getConnectionId();
        $key          = $this->keys->current($connectionId, KeyUse::CLIENT_ASSERTION);

        if ($key === null) {
            return null;
        }

        $clientId = $options->clientId();
        $pem      = $this->keys->privateKey($connectionId, $key->id);

        try {
            $assertion = $this->jose->signClientAssertion($clientId, $options->tokenEndpoint(), $pem, $this->clock->now(), $options->clientAssertionAlgorithm());
        } catch (RandomException) {
            throw self::noRandomness();
        }

        return FetchCredentials::privateKeyJwt($clientId, $assertion->reveal());
    }
}
