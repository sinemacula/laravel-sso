<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * The random protocol state the package makes for one authorisation request
 * (SSO-5.1, SSO-5.2, SSO-5.4): the state sent as the OIDC `state` or the SAML
 * `RelayState`, the OIDC nonce, and the PKCE verifier the package uses with the
 * identity provider. Each is 43 base64url characters from 32 random bytes of
 * the system's CSPRNG, independent of the request's public reference and of the
 * client's verifier.
 *
 * Each is a `Secrets\Secret`, given to the driver to send, and none is ever
 * stored as it is: the request keeps the state's and the nonce's digests (the
 * lower-case hex SHA-256) and the PKCE verifier encrypted. A dump and
 * `json_encode()` show none of them, and the state refuses to be serialised or
 * unserialised, so it never reaches a log, an exception, a queue or an event
 * (SSO-9.8).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProtocolState implements \JsonSerializable
{
    /** @var int The length of each value, in characters. */
    public const int LENGTH = 43;

    /** @var int The random bytes each value is made from: 256 bits. */
    private const int BYTES = 32;

    /** @var string What a dump and `json_encode()` show for each value. */
    private const string REDACTED = '[redacted]';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $state
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $nonce
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $codeVerifier
     */
    private function __construct(

        /** The random reference sent as OIDC `state` or SAML `RelayState`. */
        private Secret $state,

        /** The OIDC nonce. */
        private Secret $nonce,

        /** The PKCE verifier the package uses with the identity provider. */
        private Secret $codeVerifier,
    ) {}

    /**
     * What a dump shows: none of the values.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    /**
     * Refuse to be serialised: the state lives only for the start that made it.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A protocol state cannot be serialised.');
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
        throw new \LogicException('A protocol state cannot be unserialised.');
    }

    /**
     * A new state, nonce and PKCE verifier, each of 256 random bits.
     *
     * @return self
     *
     * @throws \Random\RandomException
     */
    public static function generate(): self
    {
        return new self(self::random(), self::random(), self::random());
    }

    /**
     * The state, sent as OIDC `state` or SAML `RelayState`.
     *
     * @return \SineMacula\Laravel\Sso\Secrets\Secret
     */
    public function state(): Secret
    {
        return $this->state;
    }

    /**
     * The OIDC nonce.
     *
     * @return \SineMacula\Laravel\Sso\Secrets\Secret
     */
    public function nonce(): Secret
    {
        return $this->nonce;
    }

    /**
     * The PKCE verifier the package uses with the identity provider.
     *
     * @return \SineMacula\Laravel\Sso\Secrets\Secret
     */
    public function codeVerifier(): Secret
    {
        return $this->codeVerifier;
    }

    /**
     * The lower-case hex SHA-256 of the state, the only form the request keeps
     * it in and a response is looked up by.
     *
     * @return string
     */
    public function stateDigest(): string
    {
        return hash('sha256', $this->state->reveal());
    }

    /**
     * The lower-case hex SHA-256 of the nonce, the only form the request keeps
     * it in.
     *
     * @return string
     */
    public function nonceDigest(): string
    {
        return hash('sha256', $this->nonce->reveal());
    }

    /**
     * The S256 challenge of the PKCE verifier (RFC 7636 §4.2):
     * `BASE64URL(SHA-256(verifier))` without padding.
     *
     * @return string
     */
    public function codeChallenge(): string
    {
        return self::base64Url(hash('sha256', $this->codeVerifier->reveal(), true));
    }

    /**
     * What `json_encode()` writes: none of the values.
     *
     * @return array<string, string>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['state' => self::REDACTED, 'nonce' => self::REDACTED, 'code_verifier' => self::REDACTED];
    }

    /**
     * A new random value: 32 bytes, base64url without padding.
     *
     * @return \SineMacula\Laravel\Sso\Secrets\Secret
     *
     * @throws \Random\RandomException
     */
    private static function random(): Secret
    {
        return new Secret(self::base64Url(random_bytes(self::BYTES)));
    }

    /**
     * The bytes in base64url, without padding (RFC 4648 §5).
     *
     * @param  string  $bytes
     * @return string
     */
    private static function base64Url(#[\SensitiveParameter] string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
