<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

/**
 * An authorisation request's public reference: the one flow identifier in
 * events and logs, and not a secret.
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

    /** @var int Random bytes, giving a length under the log sanitiser's 40. */
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
     * The reference, as the start response and a redirect carry it.
     *
     * @return string
     */
    #[\Override]
    public function jsonSerialize(): string
    {
        return $this->value;
    }
}
