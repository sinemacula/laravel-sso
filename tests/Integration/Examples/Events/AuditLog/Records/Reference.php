<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

/**
 * A stand-in for `laravel-audit-log`'s `Records\Reference`, with the exact
 * signature of `of()`.
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
     * Check each part is 1 to 191 characters.
     *
     * @param  string  $type
     * @param  string  $id
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** A morph class, a class name or any name the application uses. */
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
     * A reference to the type and id, an integer id kept as its decimal string.
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
