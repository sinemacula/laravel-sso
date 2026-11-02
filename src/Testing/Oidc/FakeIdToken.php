<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Oidc;

/**
 * An ID token the fake OpenID provider issues (SSO-12.4), built with every knob
 * a test needs and signed by hand (`JwsSigner`), never by the package's JOSE
 * library. Each knob answers a new token; `toString()` signs it.
 *
 * - Claims: `with()` sets any claim to any JSON value (a string `exp`, an
 *   integer `sub`, an `aud` as a string or a list), `without()` removes one,
 *   and `accessTokenHash()` sets the `at_hash` of an access token for the
 *   token's algorithm.
 * - Header: `withHeader()` and `withoutHeader()` set or remove any member
 *   (`kid`, `crit`, `b64`, `jku`, `typ`); `signedWith()` signs with another key
 *   by another algorithm, naming its `kid` or none.
 * - Raw JSON: `withHeaderJson()` and `withPayloadJson()` replace the encoded
 *   text whole, so a member can be repeated, escaped or nested twice.
 * - Hostile forms: `unsigned()` (an empty signature, as `none` has), `hmac()`
 *   (an HMAC under a secret such as a public key's PEM), `asJwe()` (five
 *   segments) and `withSignatureOf()` (another token's signature).
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
     * The token, signed.
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
     * The token with the claim set to the value.
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
     * The token signed with the key by the algorithm, its header naming the
     * key's `kid`, or none when the key has none.
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
     * The token whose `at_hash` is the access token's, for its algorithm
     * (OpenID Connect Core §3.1.3.6): the left half of the hash, encoded.
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
     * The token whose header is the JSON text given, whole.
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
     * The token whose payload is the JSON text given, whole.
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
     * `alg` is left as it is, so a test sets it.
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
     * The token with an HMAC signature under the secret, by the hash of its
     * header's algorithm size.
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
     * The token, signed as asked.
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
     * The header and payload, signed by the token's mode.
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
     * The header's `alg`, or none.
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
