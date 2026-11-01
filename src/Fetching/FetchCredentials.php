<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;

/**
 * The one credential an outbound request carries (SSO-2.9): a client
 * authentication for a token request, or an access token for UserInfo. The
 * fetcher puts it where its kind says (see `CredentialKind`); nothing else
 * reads it.
 *
 * The secret (a client secret, a signed client assertion or an access token) is
 * held in a `\SensitiveParameterValue` and never leaves the object but through
 * `secret()`, for the fetcher: no dump (PHP's own, or the one behind Laravel's
 * `dump()`, which also lists private properties), export or array cast shows
 * it, and the object refuses to be serialised, so it cannot reach a log, an
 * exception, a queue or an event (SSO-2.5, SSO-7.6).
 *
 * An access token must be an RFC 6750 b64token, so it can never put a control
 * character into the `Authorization` header it is sent in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FetchCredentials
{
    /** @var string An RFC 6750 §2.1 b64token: what an access token sent as a bearer token may hold. */
    private const string B64TOKEN = '#^[A-Za-z0-9\-._~+/]+=*$#D';

    /** @var \SensitiveParameterValue The client secret, signed client assertion or access token. */
    private \SensitiveParameterValue $secret;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind  $kind
     * @param  ?string  $clientId
     * @param  string  $secret
     */
    private function __construct(

        /** Where the credential goes. */
        public CredentialKind $kind,

        /** The connection's client id at the identity provider, for a client authentication. */
        public ?string $clientId,

        // Not promoted: held wrapped, so no dump, export or array cast shows it
        #[\SensitiveParameter]
        string $secret,
    ) {
        $this->secret = new \SensitiveParameterValue($secret);
    }

    /**
     * What a dump shows: the kind and the client id, never the secret.
     *
     * @return array<string, ?string>
     */
    public function __debugInfo(): array
    {
        return [
            'kind'     => $this->kind->value,
            'clientId' => $this->clientId,
            'secret'   => '[redacted]',
        ];
    }

    /**
     * Refuse to be serialised: a credential lives only for the request that
     * sends it.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('Outbound credentials cannot be serialised.');
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
        throw new \LogicException('Outbound credentials cannot be unserialised.');
    }

    /**
     * The client id and secret, in the `Authorization: Basic` header.
     *
     * @param  string  $clientId
     * @param  string  $clientSecret
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function clientSecretBasic(string $clientId, #[\SensitiveParameter] string $clientSecret): self
    {
        return new self(CredentialKind::CLIENT_SECRET_BASIC, self::clientId($clientId), self::nonEmpty($clientSecret));
    }

    /**
     * The client id and secret, in the form body.
     *
     * @param  string  $clientId
     * @param  string  $clientSecret
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function clientSecretPost(string $clientId, #[\SensitiveParameter] string $clientSecret): self
    {
        return new self(CredentialKind::CLIENT_SECRET_POST, self::clientId($clientId), self::nonEmpty($clientSecret));
    }

    /**
     * The client id and a client assertion the connection's key signed, in the
     * form body.
     *
     * @param  string  $clientId
     * @param  string  $assertion
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function privateKeyJwt(string $clientId, #[\SensitiveParameter] string $assertion): self
    {
        return new self(CredentialKind::PRIVATE_KEY_JWT, self::clientId($clientId), self::nonEmpty($assertion));
    }

    /**
     * The access token of a UserInfo request, refused unless it is an RFC 6750
     * b64token. The message never names the token.
     *
     * @param  string  $accessToken
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function accessToken(#[\SensitiveParameter] string $accessToken): self
    {
        if (preg_match(self::B64TOKEN, self::nonEmpty($accessToken)) !== 1) {
            throw new \InvalidArgumentException('An access token must be an RFC 6750 b64token.');
        }

        return new self(CredentialKind::ACCESS_TOKEN, null, $accessToken);
    }

    /**
     * The client secret, signed client assertion or access token, for the
     * fetcher to send and for nothing else.
     *
     * @return string
     */
    public function secret(): string
    {
        $secret = $this->secret->getValue();

        assert(is_string($secret));

        return $secret;
    }

    /**
     * The client id, refused when empty.
     *
     * @param  string  $clientId
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function clientId(string $clientId): string
    {
        if ($clientId === '') {
            throw new \InvalidArgumentException('A client authentication needs the connection\'s client id.');
        }

        return $clientId;
    }

    /**
     * The secret, refused when empty.
     *
     * @param  string  $secret
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function nonEmpty(#[\SensitiveParameter] string $secret): string
    {
        if ($secret === '') {
            throw new \InvalidArgumentException('An outbound credential cannot be empty.');
        }

        return $secret;
    }
}
