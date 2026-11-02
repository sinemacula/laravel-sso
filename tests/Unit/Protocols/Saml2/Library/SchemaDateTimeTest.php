<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\SchemaDateTime;

/**
 * Unit tests for the strict `xs:dateTime` check the metadata reader judges
 * every `validUntil` by: each field at and one past its bounds (the month, the
 * day of each kind of month and of February in leap and common years, the hour,
 * 24:00:00, the minute, the second and the zone's offset), any fractions, no
 * zone, and every form the pattern refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SchemaDateTime::class)]
final class SchemaDateTimeTest extends TestCase
{
    /**
     * Rows of `[value, valid]`: a value at or just past a bound, and whether it
     * is a real `xs:dateTime`.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideValues(): iterable
    {
        yield from [
            'the first year'                    => ['0001-01-01T00:00:00Z', true],
            'year 0000'                         => ['0000-01-01T00:00:00Z', false],
            'the last four-digit year'          => ['9999-12-31T23:59:59Z', true],
            'a five-digit year'                 => ['10000-01-01T00:00:00Z', false],
            'month 01'                          => ['2027-01-01T00:00:00Z', true],
            'month 00'                          => ['2027-00-01T00:00:00Z', false],
            'month 12'                          => ['2027-12-01T00:00:00Z', true],
            'month 13'                          => ['2027-13-01T00:00:00Z', false],
            'day 00'                            => ['2027-01-00T00:00:00Z', false],
            '31 January'                        => ['2027-01-31T00:00:00Z', true],
            '32 January'                        => ['2027-01-32T00:00:00Z', false],
            '30 April'                          => ['2027-04-30T00:00:00Z', true],
            '31 April'                          => ['2027-04-31T00:00:00Z', false],
            '28 February, a common year'        => ['2027-02-28T00:00:00Z', true],
            '29 February, a common year'        => ['2027-02-29T00:00:00Z', false],
            '29 February, a leap year'          => ['2028-02-29T00:00:00Z', true],
            '30 February, a leap year'          => ['2028-02-30T00:00:00Z', false],
            '29 February, a century'            => ['2100-02-29T00:00:00Z', false],
            '29 February, a fourth century'     => ['2000-02-29T00:00:00Z', true],
            'hour 23'                           => ['2027-01-01T23:00:00Z', true],
            'hour 25'                           => ['2027-01-01T25:00:00Z', false],
            'the end of the day'                => ['2027-01-01T24:00:00Z', true],
            'the end of the day, zero fraction' => ['2027-01-01T24:00:00.000Z', true],
            'the end of the day and a fraction' => ['2027-01-01T24:00:00.5Z', false],
            'the end of the day and a second'   => ['2027-01-01T24:00:01Z', false],
            'the end of the day and a minute'   => ['2027-01-01T24:01:00Z', false],
            'minute 59'                         => ['2027-01-01T00:59:00Z', true],
            'minute 60'                         => ['2027-01-01T00:60:00Z', false],
            'second 59'                         => ['2027-01-01T00:00:59Z', true],
            'second 60'                         => ['2027-01-01T00:00:60Z', false],
            'nine fractional digits'            => ['2027-01-01T23:59:59.999999999Z', true],
            'a dot with no fraction'            => ['2027-01-01T00:00:00.Z', false],
            'no zone'                           => ['2027-01-01T00:00:00', true],
            'offset +14:00'                     => ['2027-01-01T00:00:00+14:00', true],
            'offset -14:00'                     => ['2027-01-01T00:00:00-14:00', true],
            'offset +14:01'                     => ['2027-01-01T00:00:00+14:01', false],
            'offset -15:00'                     => ['2027-01-01T00:00:00-15:00', false],
            'offset +05:59'                     => ['2027-01-01T00:00:00+05:59', true],
            'offset +05:60'                     => ['2027-01-01T00:00:00+05:60', false],
            'a lower case zone'                 => ['2027-01-01T00:00:00z', false],
            'a space for the T'                 => ['2027-01-01 00:00:00Z', false],
            'a single-digit month'              => ['2027-1-01T00:00:00Z', false],
            'a trailing newline'                => ["2027-01-01T00:00:00Z\n", false],
            'a leading space'                   => [' 2027-01-01T00:00:00Z', false],
            'a date alone'                      => ['2027-01-01', false],
            'a word'                            => ['tomorrow', false],
            'nothing'                           => ['', false],
        ];
    }

    /**
     * A value is a real `xs:dateTime` exactly when every field is within its
     * bounds and its form is the schema's.
     *
     * @param  string  $value
     * @param  bool  $valid
     * @return void
     */
    #[DataProvider('provideValues')]
    public function testJudgesEachFieldAtItsBounds(string $value, bool $valid): void
    {
        self::assertSame($valid, SchemaDateTime::isValid($value));
    }
}
