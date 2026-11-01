<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * The client's handoff verifier (SSO-5.1, SSO-5.2, SSO-5.12): a secret the
 * client that started a flow holds for its authorisation request, whose S256
 * challenge binds the handoff code to that client, as in PKCE (RFC 7636). It is
 * independent of the PKCE verifier the package uses with the identity provider,
 * which never leaves the API.
 *
 * A verifier is 43 to 128 unreserved characters (`A-Z`, `a-z`, `0-9`, `-`, `.`,
 * `_`, `~`, RFC 7636 §4.1); one the package generates is 43 base64url
 * characters from 32 random bytes, 256 bits, returned once in the start
 * response's body and never again. It leaves the client only in the redemption
 * request, never in a URL.
 *
 * The value is held in a `\SensitiveParameterValue` and leaves the object only
 * through `reveal()`: a dump or `json_encode()` shows `[redacted]`, it has no
 * `__toString()`, and it refuses to be serialised or unserialised, so it never
 * reaches a log, an exception, a queue or an event (SSO-9.8). It is a type of
 * its own, never accepted as a handoff code or a request reference (SSO-9.2).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Verifier implements \JsonSerializable
{
    /** @var int The shortest verifier, in characters. */
    public const int MIN_LENGTH = 43;

    /** @var int The longest verifier, in characters. */
    public const int MAX_LENGTH = 128;

    /** @var int The random bytes a generated verifier is made from: 256 bits. */
    private const int BYTES = 32;

    /** @var string A verifier: 43 to 128 unreserved characters, with nothing after them. */
    private const string FORMAT = '/^[A-Za-z0-9\-._~]{43,128}$/D';

    /** @var \SensitiveParameterValue The verifier. */
    private \SensitiveParameterValue $value;

    /**
     * Constructor.
     *
     * @param  string  $value
     */
    private function __construct(#[\SensitiveParameter] string $value)
    {
        $this->value = new \SensitiveParameterValue($value);
    }

    /**
     * What a dump shows: never the verifier.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['verifier' => '[redacted]'];
    }

    /**
     * Refuse to be serialised: a verifier lives only for the request that
     * carries it.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A verifier cannot be serialised.');
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
        throw new \LogicException('A verifier cannot be unserialised.');
    }

    /**
     * A new, random verifier of 256 bits.
     *
     * @return self
     *
     * @throws \Random\RandomException
     */
    public static function generate(): self
    {
        return new self(rtrim(strtr(base64_encode(random_bytes(self::BYTES)), '+/', '-_'), '='));
    }

    /**
     * The verifier the value is.
     *
     * @param  string  $value
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromString(#[\SensitiveParameter] string $value): self
    {
        if (!self::isWellFormed($value)) {
            throw new \InvalidArgumentException(sprintf('A verifier is %d to %d unreserved characters.', self::MIN_LENGTH, self::MAX_LENGTH));
        }

        return new self($value);
    }

    /**
     * Whether the value has a verifier's form.
     *
     * @param  string  $value
     * @return bool
     */
    public static function isWellFormed(#[\SensitiveParameter] string $value): bool
    {
        return preg_match(self::FORMAT, $value) === 1;
    }

    /**
     * The verifier's S256 challenge.
     *
     * @return \SineMacula\Laravel\Sso\Flows\S256Challenge
     */
    public function challenge(): S256Challenge
    {
        return S256Challenge::of($this);
    }

    /**
     * Whether the other verifier is this one, compared in constant time.
     *
     * @param  self  $other
     * @return bool
     */
    public function equals(self $other): bool
    {
        return ConstantTime::equals($this->reveal(), $other->reveal());
    }

    /**
     * The verifier, for the start response's body and the challenge, and for
     * nothing else.
     *
     * @return string
     */
    public function reveal(): string
    {
        /** @var string */
        return $this->value->getValue();
    }

    /**
     * What `json_encode()` writes: never the verifier.
     *
     * @return string
     */
    #[\Override]
    public function jsonSerialize(): string
    {
        return '[redacted]';
    }
}
