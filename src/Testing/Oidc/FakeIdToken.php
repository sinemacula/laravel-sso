<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Oidc;

/**
 * An immutable builder for the fake provider's ID tokens, signed by `JwsSigner`
 * and never by the package's JOSE library.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeIdToken implements \Stringable
{
    /** @var array<int, string> The hash of each algorithm size, for `at_hash`. */
    private const array HASHES = [256 => 'sha256', 384 => 'sha384', 512 => 'sha512'];

    /** @var ?string The header's JSON text, when a test gave it whole. */
    private ?string $headerJson = null;

    /** @var ?string The payload's JSON text, when a test gave it whole. */
    private ?string $payloadJson = null;

    /** @var string How the token is signed: `sign`, `hmac`, `none` or `jwe`. */
    private string $mode = 'sign';

    /** @var string The HMAC secret, for `hmac`. */
    private string $secret = '';

    /** @var ?string The signature segment taken from another token. */
    private ?string $signature = null;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @param  array<string, mixed>  $header
     * @param  array<string, mixed>  $claims
     */
    public function __construct(

        /** The key the token is signed with. */
        private FakeSigningKey $key,

        /** The protected header. */
        private array $header,

        /** The claims. */
        private array $claims,
    ) {}

    /**
     * Sign the token.
     *
     * @return string
     *
     * @throws \LogicException
     */
    #[\Override]
    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * The claims as they stand.
     *
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return $this->claims;
    }

    /**
     * The header as it stands.
     *
     * @return array<string, mixed>
     */
    public function header(): array
    {
        return $this->header;
    }

    /**
     * The token with the claim set to any JSON value.
     *
     * @param  string  $claim
     * @param  mixed  $value
     * @return self
     */
    public function with(string $claim, mixed $value): self
    {
        $token                 = clone $this;
        $token->claims[$claim] = $value;

        return $token;
    }

    /**
     * The token without the claim.
     *
     * @param  string  $claim
     * @return self
     */
    public function without(string $claim): self
    {
        $token = clone $this;

        unset($token->claims[$claim]);

        return $token;
    }

    /**
     * The token with the header member set to the value.
     *
     * @param  string  $name
     * @param  mixed  $value
     * @return self
     */
    public function withHeader(string $name, mixed $value): self
    {
        $token                = clone $this;
        $token->header[$name] = $value;

        return $token;
    }

    /**
     * The token without the header member.
     *
     * @param  string  $name
     * @return self
     */
    public function withoutHeader(string $name): self
    {
        $token = clone $this;

        unset($token->header[$name]);

        return $token;
    }

    /**
     * The token signed with another key and algorithm, naming the key's `kid`
     * if it has one.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @param  string  $algorithm
     * @return self
     */
    public function signedWith(FakeSigningKey $key, string $algorithm): self
    {
        $token         = clone $this;
        $token->key    = $key;
        $token->header = array_filter([...$token->header, 'alg' => $algorithm, 'kid' => $key->kid], static fn (mixed $value): bool => $value !== null);

        return $token;
    }

    /**
     * The token with the access token's `at_hash` for its algorithm.
     *
     * @param  string  $accessToken
     * @return self
     */
    public function accessTokenHash(#[\SensitiveParameter] string $accessToken): self
    {
        $digest = hash($this->hash(), $accessToken, true);

        return $this->with('at_hash', JwsSigner::encode(substr($digest, 0, intdiv(strlen($digest), 2))));
    }

    /**
     * The token with the header's JSON text replaced whole, so a member can
     * repeat.
     *
     * @param  string  $json
     * @return self
     */
    public function withHeaderJson(string $json): self
    {
        $token             = clone $this;
        $token->headerJson = $json;

        return $token;
    }

    /**
     * The token with the payload's JSON text replaced whole.
     *
     * @param  string  $json
     * @return self
     */
    public function withPayloadJson(string $json): self
    {
        $token              = clone $this;
        $token->payloadJson = $json;

        return $token;
    }

    /**
     * The token with an empty signature, as `alg` `none` has it; the header's
     * `alg` is left for the test to set.
     *
     * @return self
     */
    public function unsigned(): self
    {
        $token       = clone $this;
        $token->mode = 'none';

        return $token;
    }

    /**
     * The token with an HMAC signature under the secret.
     *
     * @param  string  $secret
     * @return self
     */
    public function hmac(#[\SensitiveParameter] string $secret): self
    {
        $token         = clone $this;
        $token->mode   = 'hmac';
        $token->secret = $secret;

        return $token;
    }

    /**
     * The token as five segments, as a JWE has.
     *
     * @return self
     */
    public function asJwe(): self
    {
        $token       = clone $this;
        $token->mode = 'jwe';

        return $token;
    }

    /**
     * The token carrying another token's signature segment.
     *
     * @param  string  $other
     * @return self
     */
    public function withSignatureOf(string $other): self
    {
        $token            = clone $this;
        $token->signature = explode('.', $other)[2] ?? '';

        return $token;
    }

    /**
     * Sign the token by its mode.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function toString(): string
    {
        $token = $this->signed($this->headerJson ?? $this->header, $this->payloadJson ?? $this->claims);

        [$header, $payload] = explode('.', $token);

        return $this->signature === null ? $token : $header . '.' . $payload . '.' . $this->signature;
    }

    /**
     * Sign the header and payload by the token's mode.
     *
     * @param  array<string, mixed>|string  $header
     * @param  array<string, mixed>|string  $payload
     * @return string
     *
     * @throws \LogicException
     */
    private function signed(array|string $header, array|string $payload): string
    {
        return match ($this->mode) {
            'none'  => JwsSigner::unsigned($header, $payload),
            'hmac'  => JwsSigner::hmac($header, $payload, $this->secret, $this->hash()),
            'jwe'   => JwsSigner::unsigned($header, $payload) . 'AAAA.AAAA.AAAA',
            default => JwsSigner::sign($header, $payload, $this->key, $this->algorithm()),
        };
    }

    /**
     * The header's `alg`, or an empty string.
     *
     * @return string
     */
    private function algorithm(): string
    {
        $algorithm = $this->header['alg'] ?? null;

        return is_string($algorithm) ? $algorithm : '';
    }

    /**
     * The hash of the header's algorithm size, SHA-256 by default.
     *
     * @return string
     */
    private function hash(): string
    {
        return self::HASHES[substr($this->algorithm(), 2)] ?? 'sha256';
    }
}
