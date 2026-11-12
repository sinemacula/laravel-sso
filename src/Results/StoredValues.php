<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

use Carbon\CarbonImmutable;

/**
 * Shared checks and stored forms for a verified result, so built and restored
 * results are judged the same way. No message names the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StoredValues
{
    /** @var string The form an instant is stored in: UTC, to the microsecond. */
    public const string INSTANT_FORMAT = 'Y-m-d\TH:i:s.u\Z';

    /** @var string Shown in redacted JSON in place of a provider value. */
    public const string REDACTED = '[redacted]';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * `[redacted]` for a stated value, `null` for none.
     *
     * @param  mixed  $value
     * @return ?string
     */
    public static function redacted(#[\SensitiveParameter] mixed $value): ?string
    {
        return $value === null ? null : self::REDACTED;
    }

    /**
     * Refuse a string that is empty or longer than the bytes allowed.
     *
     * @param  string  $name
     * @param  string  $value
     * @param  int  $maxBytes
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertText(string $name, string $value, int $maxBytes): void
    {
        if ($value === '' || strlen($value) > $maxBytes) {
            throw new \InvalidArgumentException(sprintf('A verified result\'s %s is 1 to %d bytes.', $name, $maxBytes));
        }
    }

    /**
     * Refuse a given string that is empty or longer than the bytes allowed.
     *
     * @param  string  $name
     * @param  ?string  $value
     * @param  int  $maxBytes
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertOptionalText(string $name, ?string $value, int $maxBytes): void
    {
        if ($value === null) {
            return;
        }

        self::assertText($name, $value, $maxBytes);
    }

    /**
     * The instant in its stored form, or `null`.
     *
     * @param  ?\Carbon\CarbonImmutable  $instant
     * @return ?string
     */
    public static function instant(?CarbonImmutable $instant): ?string
    {
        return $instant?->utc()->format(self::INSTANT_FORMAT);
    }

    /**
     * The instant a stored value names.
     *
     * @param  mixed  $value
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \UnexpectedValueException
     */
    public static function restoredInstant(mixed $value): ?CarbonImmutable
    {
        if ($value === null) {
            return null;
        }

        try {
            $instant = is_string($value) ? CarbonImmutable::createFromFormat(self::INSTANT_FORMAT, $value, 'UTC') : null;
        } catch (\InvalidArgumentException) {
            $instant = null;
        }

        if (!$instant instanceof CarbonImmutable || $instant->format(self::INSTANT_FORMAT) !== $value) {
            throw self::corrupt();
        }

        return $instant;
    }

    /**
     * The stored string under the key.
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $key
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public static function string(array $stored, string $key): string
    {
        $value = $stored[$key] ?? null;

        if (!is_string($value)) {
            throw self::corrupt();
        }

        return $value;
    }

    /**
     * The stored string under the key, or `null` when it is `null` or absent.
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $key
     * @return ?string
     *
     * @throws \UnexpectedValueException
     */
    public static function optionalString(array $stored, string $key): ?string
    {
        return ($stored[$key] ?? null) === null ? null : self::string($stored, $key);
    }

    /**
     * The stored array under the key.
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $key
     * @return array<array-key, mixed>
     *
     * @throws \UnexpectedValueException
     */
    public static function array(array $stored, string $key): array
    {
        $value = $stored[$key] ?? null;

        if (!is_array($value)) {
            throw self::corrupt();
        }

        return $value;
    }

    /**
     * The stored boolean under the key; anything else is corrupt.
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $key
     * @return bool
     *
     * @throws \UnexpectedValueException
     */
    public static function isTrue(array $stored, string $key): bool
    {
        $value = $stored[$key] ?? null;

        if (!is_bool($value)) {
            throw self::corrupt();
        }

        return $value;
    }

    /**
     * The stored array under the key, or `null` when it is `null` or absent.
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $key
     * @return ?array<array-key, mixed>
     *
     * @throws \UnexpectedValueException
     */
    public static function optionalArray(array $stored, string $key): ?array
    {
        return ($stored[$key] ?? null) === null ? null : self::array($stored, $key);
    }

    /**
     * The exception for stored data that is not what was written.
     *
     * @return \UnexpectedValueException
     */
    public static function corrupt(): \UnexpectedValueException
    {
        return new \UnexpectedValueException('A stored verified result is not one the package wrote.');
    }

    /**
     * Rethrow what a constructor refused while restoring as corrupt storage.
     *
     * @template T
     *
     * @param  \Closure(): T  $restore
     * @return T
     *
     * @throws \UnexpectedValueException
     */
    public static function restoring(\Closure $restore): mixed
    {
        try {
            return $restore();
        } catch (\InvalidArgumentException|\TypeError|\ValueError) {
            throw self::corrupt();
        }
    }
}
