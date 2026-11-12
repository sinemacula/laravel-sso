<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Secrets;

/**
 * A plaintext secret that leaves the object only through `reveal()`.
 *
 * Redacted in dumps and JSON, unserialisable, and deliberately without
 * `__toString()`, so it cannot leak into a log by interpolation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Secret implements \JsonSerializable
{
    /** @var \SensitiveParameterValue The plaintext secret. */
    private \SensitiveParameterValue $secret;

    /**
     * Constructor.
     *
     * @param  string  $secret
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(#[\SensitiveParameter] string $secret)
    {
        if ($secret === '') {
            throw new \InvalidArgumentException('A secret cannot be empty.');
        }

        $this->secret = new \SensitiveParameterValue($secret);
    }

    /**
     * What a dump shows: never the secret.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['secret' => '[redacted]'];
    }

    /**
     * Refuse to be serialised, so it never reaches a queue, cache or session.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A secret cannot be serialised.');
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
        throw new \LogicException('A secret cannot be unserialised.');
    }

    /**
     * The plaintext, for the code that must send or use it.
     *
     * @return string
     */
    public function reveal(): string
    {
        $secret = $this->secret->getValue();

        assert(is_string($secret));

        return $secret;
    }

    /**
     * Whether the given value is the secret, compared in constant time.
     *
     * @param  string  $given
     * @return bool
     */
    public function equals(#[\SensitiveParameter] string $given): bool
    {
        return ConstantTime::equals($this->reveal(), $given);
    }

    /**
     * What `json_encode()` writes: never the secret.
     *
     * @return string
     */
    #[\Override]
    public function jsonSerialize(): string
    {
        return '[redacted]';
    }
}
