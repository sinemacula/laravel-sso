<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

/**
 * Whether a value is a real `xs:dateTime` (XML Schema Part 2, 3.2.7), judged
 * strictly, as the metadata reader judges every `validUntil` it reads before it
 * parses one: a four-digit year from 0001, a month and a day that name a real
 * date (29 February in a leap year alone), an hour to 23, or 24:00:00 for the
 * end of the day, minutes and seconds to 59, any fractions of a second, and no
 * zone, `Z` or an offset of at most 14 hours.
 *
 * A date parser rolls a value out of range over into the next month, day or
 * hour, or refuses it with a message that quotes it; this answers a value that
 * is not one with `false` alone, so neither reaches the reader.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SchemaDateTime
{
    /** @var string An `xs:dateTime`'s form, each field named. */
    private const string PATTERN = '/^(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})'
        . 'T(?<hour>\d{2}):(?<minute>\d{2}):(?<second>\d{2})(?<fraction>\.\d+)?(?<zone>Z|[+-]\d{2}:\d{2})?$/D';

    /** @var int The largest offset a zone may name, in minutes (14 hours). */
    private const int MAX_OFFSET_MINUTES = 840;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the value is a real `xs:dateTime` of a four-digit year.
     *
     * @param  string  $value
     * @return bool
     */
    public static function isValid(string $value): bool
    {
        if (preg_match(self::PATTERN, $value, $parts) !== 1) {
            return false;
        }

        $dated = checkdate((int) $parts['month'], (int) $parts['day'], (int) $parts['year']) && self::isZone($parts['zone'] ?? 'Z');

        return $dated && self::isTime($parts);
    }

    /**
     * Whether the time of day is real: to 23:59:59, or 24:00:00 with no
     * fraction other than zeros.
     *
     * @param  array<array-key, string>  $parts
     * @return bool
     */
    private static function isTime(array $parts): bool
    {
        $hour   = (int) ($parts['hour'] ?? '');
        $minute = (int) ($parts['minute'] ?? '');
        $second = (int) ($parts['second'] ?? '');

        if ($hour === 24) {
            return $minute + $second === 0 && rtrim($parts['fraction'] ?? '', '.0') === '';
        }

        return $hour < 24 && max($minute, $second) < 60;
    }

    /**
     * Whether the zone is `Z` or an offset of at most 14 hours, its minutes to
     * 59.
     *
     * @param  string  $zone
     * @return bool
     */
    private static function isZone(string $zone): bool
    {
        if ($zone === 'Z') {
            return true;
        }

        $hours   = (int) substr($zone, 1, 2);
        $minutes = (int) substr($zone, 4, 2);

        return $minutes < 60 && $hours * 60 + $minutes <= self::MAX_OFFSET_MINUTES;
    }
}
