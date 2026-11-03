<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

/**
 * An authorisation request's public reference (SSO-5.1, SSO-9.8): the one flow
 * identifier the package returns to the client, puts on a completion's redirect
 * and carries in events and logs, under `request_reference`.
 *
 * It is 32 base64url characters from 24 random bytes, so it is unguessable and
 * stays under the 40-character run the log sanitiser redacts. It is not a
 * secret and grants nothing: it is never the OIDC `state` or the SAML
 * `RelayState` (random references of their own), never a verifier and never a
 * handoff code, each a distinct type the package never accepts as another
 * (SSO-5.2, SSO-9.2).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RequestReference implements \JsonSerializable, \Stringable
{
    /** @var int The length of a reference, in characters. */
    public const int LENGTH = 32;

    /** @var int The random bytes a reference is made from. */
    private const int BYTES = 24;

    /** @var string A reference: exactly 32 base64url characters. */
    private const string FORMAT = '/^[A-Za-z0-9_-]{32}$/D';

    /**
     * Constructor.
     *
     * @param  string  $value
     */
    private function __construct(

        /** The reference. */
        public string $value,
    ) {}

    /**
     * The reference.
     *
     * @return string
     */
    #[\Override]
    public function __toString(): string
    {
        return $this->value;
    }

    /**
     * A new, random reference.
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
     * The reference the value is.
     *
     * @param  string  $value
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromString(string $value): self
    {
        if (!self::isWellFormed($value)) {
            throw new \InvalidArgumentException(sprintf('A request reference is %d base64url characters.', self::LENGTH));
        }

        return new self($value);
    }

    /**
     * Whether the value has a reference's form.
     *
     * @param  string  $value
     * @return bool
     */
    public static function isWellFormed(string $value): bool
    {
        return preg_match(self::FORMAT, $value) === 1;
    }

    /**
     * Whether the other reference is this one.
     *
     * @param  self  $other
     * @return bool
     */
    public function is(self $other): bool
    {
        return $this->value === $other->value;
    }

    /**
     * The reference, as the start response and a completion's redirect carry
     * it.
     *
     * @return string
     */
    #[\Override]
    public function jsonSerialize(): string
    {
        return $this->value;
    }
}
