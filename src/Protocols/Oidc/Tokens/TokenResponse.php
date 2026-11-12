<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Tokens;

/**
 * The tokens a token endpoint returned for an authorisation code, redacted from
 * dumps and JSON and never serialisable; a refresh token is never kept.
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

        // Not promoted: held wrapped
        #[\SensitiveParameter]
        string $idToken,

        // Not promoted: held wrapped
        #[\SensitiveParameter]
        string $accessToken,

        /** The token type as the provider gave it, `Bearer` in any case. */
        public string $tokenType = 'Bearer',
    ) {
        $this->idToken     = new \SensitiveParameterValue($idToken);
        $this->accessToken = new \SensitiveParameterValue($accessToken);
    }

    /**
     * Show the token type and never a token.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['id_token' => '[redacted]', 'access_token' => '[redacted]', 'token_type' => $this->tokenType];
    }

    /**
     * Refuse to be serialised; the provider's tokens are never kept.
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
     * Encode the same redacted view as a dump.
     *
     * @return array<string, string>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * The compact ID token, for its validation only.
     *
     * @return string
     */
    public function idToken(): string
    {
        /** @var string */
        return $this->idToken->getValue();
    }

    /**
     * The access token, for `at_hash` and the UserInfo request only.
     *
     * @return string
     */
    public function accessToken(): string
    {
        /** @var string */
        return $this->accessToken->getValue();
    }
}
