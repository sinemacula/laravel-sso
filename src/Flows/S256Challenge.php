<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * The S256 challenge of a client's handoff verifier (RFC 7636 §4.2, SSO-5.1,
 * SSO-9.2): `BASE64URL(SHA-256(verifier))` without padding, 43 characters. A
 * start takes it from the client, or makes it from the verifier the package
 * generates; the authorisation request and the handoff code keep it, and a
 * redemption is accepted only with the verifier it was made from.
 *
 * It is public by design, so it may be stored and shown, but it is never logged
 * or put in an event; it is a type of its own, never accepted as a verifier, a
 * handoff code or a request reference (SSO-9.2). Matching a verifier recomputes
 * its challenge and compares the two in constant time (SSO-11.9).
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
     * Whether the verifier is the one the challenge was made from, compared in
     * constant time.
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
