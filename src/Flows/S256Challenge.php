<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * The S256 challenge of a client's handoff verifier (RFC 7636 section 4.2).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class S256Challenge
{
    /** @var int The length of a challenge, in characters. */
    public const int LENGTH = 43;

    /** @var string A challenge: exactly 43 base64url characters. */
    private const string FORMAT = '/^[A-Za-z0-9_-]{43}$/D';

    /**
     * Constructor.
     *
     * @param  string  $value
     */
    private function __construct(

        /** The challenge. */
        public string $value,
    ) {}

    /**
     * The challenge the value is.
     *
     * @param  string  $value
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromString(string $value): self
    {
        if (!self::isWellFormed($value)) {
            throw new \InvalidArgumentException(sprintf('An S256 challenge is %d base64url characters.', self::LENGTH));
        }

        return new self($value);
    }

    /**
     * Whether the value has a challenge's form.
     *
     * @param  string  $value
     * @return bool
     */
    public static function isWellFormed(string $value): bool
    {
        return preg_match(self::FORMAT, $value) === 1;
    }

    /**
     * The S256 challenge of the verifier.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Verifier  $verifier
     * @return self
     */
    public static function of(Verifier $verifier): self
    {
        return new self(self::digest($verifier->reveal()));
    }

    /**
     * Whether the challenge was made from the verifier, compared in constant
     * time.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Verifier  $verifier
     * @return bool
     */
    public function isSatisfiedBy(Verifier $verifier): bool
    {
        return ConstantTime::equals($this->value, self::digest($verifier->reveal()));
    }

    /**
     * `BASE64URL(SHA-256(value))`, without padding.
     *
     * @param  string  $value
     * @return string
     */
    private static function digest(#[\SensitiveParameter] string $value): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $value, true)), '+/', '-_'), '=');
    }
}
