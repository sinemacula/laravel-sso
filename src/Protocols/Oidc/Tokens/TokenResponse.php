<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Tokens;

/**
 * What a token endpoint answered an authorisation code with, once the callback
 * read it (SSO-7.2, SSO-7.6): the ID token, the access token and the token
 * type. A refresh token, and anything else the response carried, is never kept.
 *
 * The provider's tokens are used only during the completion that received them:
 * they are held in `\SensitiveParameterValue`, given only through `idToken()`
 * and `accessToken()` to the ID token validation and the UserInfo request, and
 * never stored, returned, logged or put in an event. A dump and JSON encoding
 * show the token type and nothing of a token, and the response refuses to be
 * serialised or unserialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TokenResponse implements \JsonSerializable
{
    /** @var \SensitiveParameterValue The ID token, compact. */
    private \SensitiveParameterValue $idToken;

    /** @var \SensitiveParameterValue The access token. */
    private \SensitiveParameterValue $accessToken;

    /**
     * Constructor.
     *
     * @param  string  $idToken
     * @param  string  $accessToken
     * @param  string  $tokenType
     */
    public function __construct(

        // The ID token, compact; held wrapped
        #[\SensitiveParameter]
        string $idToken,

        // The access token; held wrapped
        #[\SensitiveParameter]
        string $accessToken,

        /** The token type, as the provider gave it (`Bearer`, in any case). */
        public string $tokenType = 'Bearer',
    ) {
        $this->idToken     = new \SensitiveParameterValue($idToken);
        $this->accessToken = new \SensitiveParameterValue($accessToken);
    }

    /**
     * What a dump shows: the token type, never a token.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['id_token' => '[redacted]', 'access_token' => '[redacted]', 'token_type' => $this->tokenType];
    }

    /**
     * Refuse to be serialised: the provider's tokens are never kept (SSO-7.6).
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A token response cannot be serialised.');
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
        throw new \LogicException('A token response cannot be unserialised.');
    }

    /**
     * What JSON encoding shows: the same as a dump, never a token.
     *
     * @return array<string, string>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * The ID token, compact, for its validation and nothing else.
     *
     * @return string
     */
    public function idToken(): string
    {
        /** @var string */
        return $this->idToken->getValue();
    }

    /**
     * The access token, for `at_hash` and the UserInfo request and nothing
     * else.
     *
     * @return string
     */
    public function accessToken(): string
    {
        /** @var string */
        return $this->accessToken->getValue();
    }
}
