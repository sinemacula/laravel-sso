<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * A single-use handoff code carrying a verified result to the client that
 * started the flow; stores keep only its digest.
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
     * Dump without the code.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['code' => '[redacted]'];
    }

    /**
     * Refuse to be serialised.
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
     * The hex SHA-256 of the code, the only form a store keeps.
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
     * The code, for the completion's redirect and the store's digest only.
     *
     * @return string
     */
    public function reveal(): string
    {
        /** @var string */
        return $this->value->getValue();
    }

    /**
     * Encode without the code.
     *
     * @return string
     */
    #[\Override]
    public function jsonSerialize(): string
    {
        return '[redacted]';
    }
}
