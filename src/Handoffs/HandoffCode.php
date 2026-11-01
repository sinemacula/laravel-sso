<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * A handoff code (SSO-9.2): the single-use, short-lived code a completion puts
 * on the application's redirect URI, which carries a verified result from the
 * API to the client that started the flow, bound to its verifier.
 *
 * A code the package issues is 43 base64url characters from 32 random bytes;
 * its store keeps only its SHA-256 digest (`digest()`), and a presented code is
 * matched against a digest in constant time (SSO-11.9).
 *
 * The value is held in a `\SensitiveParameterValue` and leaves the object only
 * through `reveal()`: a dump or `json_encode()` shows `[redacted]`, it has no
 * `__toString()`, and it refuses to be serialised or unserialised, so it never
 * reaches a log, an exception, a queue or an event (SSO-9.8). It is a type of
 * its own, never accepted as a verifier or a request reference, nor as a token
 * (SSO-9.2, AUTH-5.7).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class HandoffCode implements \JsonSerializable
{
    /** @var int The length of a code, in characters. */
    public const int LENGTH = 43;

    /** @var int The random bytes a code is made from: 256 bits. */
    private const int BYTES = 32;

    /** @var string A code: exactly 43 base64url characters. */
    private const string FORMAT = '/^[A-Za-z0-9_-]{43}$/D';

    /** @var \SensitiveParameterValue The code. */
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
     * What a dump shows: never the code.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['code' => '[redacted]'];
    }

    /**
     * Refuse to be serialised: a code lives only for the response that carries
     * it and the request that redeems it.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A handoff code cannot be serialised.');
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
        throw new \LogicException('A handoff code cannot be unserialised.');
    }

    /**
     * A new, random code of 256 bits.
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
     * The code the value is.
     *
     * @param  string  $value
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromString(#[\SensitiveParameter] string $value): self
    {
        if (!self::isWellFormed($value)) {
            throw new \InvalidArgumentException(sprintf('A handoff code is %d base64url characters.', self::LENGTH));
        }

        return new self($value);
    }

    /**
     * Whether the value has a code's form.
     *
     * @param  string  $value
     * @return bool
     */
    public static function isWellFormed(#[\SensitiveParameter] string $value): bool
    {
        return preg_match(self::FORMAT, $value) === 1;
    }

    /**
     * The lower-case hex SHA-256 digest of the code, the only form a store
     * keeps.
     *
     * @return string
     */
    public function digest(): string
    {
        return hash('sha256', $this->reveal());
    }

    /**
     * Whether the code hashes to the digest, compared in constant time.
     *
     * @param  string  $digest
     * @return bool
     */
    public function matches(string $digest): bool
    {
        return ConstantTime::matchesDigest($digest, $this->reveal());
    }

    /**
     * The code, for the completion's redirect and the store's digest, and for
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
     * What `json_encode()` writes: never the code.
     *
     * @return string
     */
    #[\Override]
    public function jsonSerialize(): string
    {
        return '[redacted]';
    }
}
