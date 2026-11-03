<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

/**
 * A stand-in for `laravel-audit-log`'s real `Records\Reference`, which this
 * package does not install, with the exact signature of the `of()` the guide's
 * mapper calls (`docs/guides/events.md`): a type and an id, each 1 to 191
 * characters, an integer id kept as its decimal string.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Reference
{
    /** @var int Longest type or id, in characters. */
    public const int MAX_CHARACTERS = 191;

    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  string  $id
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** The type: a morph class, a class name or any name the application uses. */
        public string $type,

        /** The id, exactly as given, as a string. */
        public string $id,
    ) {
        foreach (['type' => $type, 'id' => $id] as $part => $value) {
            if ($value === '' || mb_strlen($value, 'UTF-8') > self::MAX_CHARACTERS) {
                throw new \InvalidArgumentException(sprintf('A reference\'s %s must be from 1 to %d characters, with no control characters.', $part, self::MAX_CHARACTERS));
            }
        }
    }

    /**
     * A reference to the type and id given; an integer id is kept as its
     * decimal string.
     *
     * @param  string  $type
     * @param  int|string  $id
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(string $type, int|string $id): self
    {
        return new self($type, (string) $id);
    }
}
