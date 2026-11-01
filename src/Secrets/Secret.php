<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Secrets;

/**
 * One plaintext secret, held for the code that must send or use it (SSO-2.5,
 * SSO-11.9): a client secret on its way to the identity provider, a private key
 * on its way to a signature.
 *
 * The secret is held in a `\SensitiveParameterValue` and leaves the object only
 * through `reveal()`. A dump, by PHP's own functions, a debugger or Laravel's
 * helpers (which also list private properties), shows `[redacted]`, as does
 * `json_encode()`; the object refuses to be serialised or unserialised, so it
 * cannot reach a queue, a cache or a session; and it has no `__toString()`, so
 * a cast to a string, or interpolation into a message, fails loudly rather than
 * writing the secret into a log or an exception. A comparison with it is in
 * constant time.
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
     * Refuse to be serialised: a secret is decrypted for the call that uses it
     * and lives no longer.
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
     * The plaintext secret, for the code that must send or use it and for
     * nothing else.
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
