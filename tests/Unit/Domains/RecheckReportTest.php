<?php

declare(strict_types = 1);

namespace Tests\Unit\Domains;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Domains\RecheckEntry;
use SineMacula\Laravel\Sso\Domains\RecheckReport;

/**
 * Unit tests for the report of a recheck run and its entries: the entries in
 * the order they were checked, the count of each outcome, whether a lookup
 * failed, and the encoding, with snake_case keys and times in UTC.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecheckReport::class)]
#[CoversClass(RecheckEntry::class)]
final class RecheckReportTest extends TestCase
{
    /**
     * The entries are kept in the order given, and each outcome is counted,
     * none as zero.
     *
     * @return void
     */
    public function testKeepsTheEntriesInOrderAndCountsEachOutcome(): void
    {
        $entries = [
            self::entry('a.example.com', RecheckOutcome::SUSPENDED),
            self::entry('b.example.com', RecheckOutcome::CONFIRMED),
            self::entry('c.example.com', RecheckOutcome::CONFIRMED),
            self::entry('d.example.com', RecheckOutcome::SKIPPED),
        ];

        $report = new RecheckReport($entries);

        self::assertSame($entries, $report->entries);
        self::assertSame(2, $report->count(RecheckOutcome::CONFIRMED));
        self::assertSame(1, $report->count(RecheckOutcome::SUSPENDED));
        self::assertSame(1, $report->count(RecheckOutcome::SKIPPED));
        self::assertSame(0, $report->count(RecheckOutcome::LAPSED));
        self::assertFalse($report->hasLookupFailures());
    }

    /**
     * One failed lookup is enough for the report to have lookup failures; an
     * empty report has none.
     *
     * @return void
     */
    public function testHasLookupFailuresWhenALookupFailed(): void
    {
        $report = new RecheckReport([
            self::entry('a.example.com', RecheckOutcome::CONFIRMED),
            self::entry('b.example.com', RecheckOutcome::LOOKUP_FAILED),
        ]);

        self::assertTrue($report->hasLookupFailures());
        self::assertSame(1, $report->count(RecheckOutcome::LOOKUP_FAILED));
        self::assertFalse((new RecheckReport)->hasLookupFailures());
        self::assertSame([], (new RecheckReport)->entries);
    }

    /**
     * An entry encodes with snake_case keys and its lapse time in UTC, whatever
     * the timezone it was given in, or `null`.
     *
     * @return void
     */
    public function testAnEntryEncodesWithSnakeCaseKeysAndUtcTimes(): void
    {
        $lapsesAt = CarbonImmutable::parse('2026-11-04T10:30:00', 'Europe/Paris');

        $suspended = new RecheckEntry('01jbdomain0000000000000000', '01jbconnection000000000000', 'example.com', RecheckOutcome::SUSPENDED, $lapsesAt);
        $confirmed = self::entry('example.org', RecheckOutcome::CONFIRMED);

        self::assertSame([
            'domain_id'     => '01jbdomain0000000000000000',
            'connection_id' => '01jbconnection000000000000',
            'domain'        => 'example.com',
            'outcome'       => 'suspended',
            'lapses_at'     => '2026-11-04T09:30:00Z',
        ], $suspended->jsonSerialize());

        self::assertNull($confirmed->jsonSerialize()['lapses_at']);
        self::assertSame($lapsesAt, $suspended->lapsesAt);
    }

    /**
     * A report encodes every entry, in order, and the count of every outcome.
     *
     * @return void
     */
    public function testAReportEncodesItsEntriesAndCounts(): void
    {
        $report = new RecheckReport([
            self::entry('a.example.com', RecheckOutcome::LAPSED),
            self::entry('b.example.com', RecheckOutcome::RESTORED),
        ]);

        $encoded = json_decode((string) json_encode($report), true);

        self::assertIsArray($encoded);
        self::assertIsArray($encoded['counts']);

        $counts   = $encoded['counts'];
        $expected = ['confirmed' => 0, 'restored' => 1, 'suspended' => 0, 'still_failing' => 0, 'lapsed' => 1, 'lookup_failed' => 0, 'skipped' => 0];

        ksort($counts);
        ksort($expected);

        self::assertSame(['a.example.com', 'b.example.com'], array_column($encoded['entries'], 'domain'));
        self::assertSame(['lapsed', 'restored'], array_column($encoded['entries'], 'outcome'));
        self::assertSame($expected, $counts);
        self::assertEqualsCanonicalizing(
            ['domain_id', 'connection_id', 'domain', 'outcome', 'lapses_at'],
            array_keys($encoded['entries'][0]),
        );
    }

    /**
     * An entry of the domain with the outcome, no lapse time.
     *
     * @param  string  $domain
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome  $outcome
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     */
    private static function entry(string $domain, RecheckOutcome $outcome): RecheckEntry
    {
        return new RecheckEntry('01jb' . str_pad(substr(md5($domain), 0, 22), 22, '0'), '01jbconnection000000000000', $domain, $outcome);
    }
}
