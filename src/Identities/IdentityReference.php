<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Identities;

/**
 * An opaque reference to an application identity: a type and an id.
 *
 * The package never loads or interprets an identity; references match only byte
 * for byte.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentityReference implements \JsonSerializable
{
    /** @var int The longest type or id kept, in bytes. */
    public const int MAX_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  string  $id
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity's type (for an Eloquent identity, its morph class). */
        public string $type,

        /** The identity's id. */
        public string $id,
    ) {
        if (!self::isValid($type) || !self::isValid($id)) {
            throw new \InvalidArgumentException(sprintf('An identity reference has a type and an id, each 1 to %d bytes.', self::MAX_LENGTH));
        }
    }

    /**
     * The reference two nullable columns hold, or `null` when either is `null`.
     *
     * @param  ?string  $type
     * @param  ?string  $id
     * @return ?self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromColumns(?string $type, ?string $id): ?self
    {
        return $type === null || $id === null ? null : new self($type, $id);
    }

    /**
     * Whether the reference names the same identity as the other.
     *
     * @param  self  $other
     * @return bool
     */
    public function is(self $other): bool
    {
        return $this->type === $other->type && $this->id === $other->id;
    }

    /**
     * The reference, with snake_case keys.
     *
     * @return array{type: string, id: string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['type' => $this->type, 'id' => $this->id];
    }

    /**
     * Whether the part is 1 to `MAX_LENGTH` bytes.
     *
     * @param  string  $part
     * @return bool
     */
    private static function isValid(string $part): bool
    {
        return $part !== '' && strlen($part) <= self::MAX_LENGTH;
    }
}
