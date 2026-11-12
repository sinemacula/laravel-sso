<?php

declare(strict_types = 1);

namespace Tests\Unit\Domains;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Domains\DnsLookup;
use SineMacula\Laravel\Sso\Domains\Enums\DnsLookupStatus;

/**
 * Unit tests for a TXT lookup's answer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DnsLookup::class)]
final class DnsLookupTest extends TestCase
{
    /** @var string A record value a test looks for in every rendering. */
    private const string RECORD = 'attacker-chosen-record-value';

    /**
     * Each outcome says which it is, and only a found lookup holds records.
     *
     * @return void
     */
    public function testTellsTheThreeOutcomesApart(): void
    {
        $found  = DnsLookup::found([self::RECORD, 'second']);
        $absent = DnsLookup::absent();
        $failed = DnsLookup::lookupFailed();

        self::assertSame(DnsLookupStatus::FOUND, $found->status);
        self::assertSame([true, false, false], [$found->isFound(), $found->isAbsent(), $found->isLookupFailed()]);
        self::assertSame([false, true, false], [$absent->isFound(), $absent->isAbsent(), $absent->isLookupFailed()]);
        self::assertSame([false, false, true], [$failed->isFound(), $failed->isAbsent(), $failed->isLookupFailed()]);
        self::assertSame([self::RECORD, 'second'], $found->records());
        self::assertSame([], $absent->records());
        self::assertSame([], $failed->records());
    }

    /**
     * A found lookup holds at least one record.
     *
     * @return void
     */
    public function testAFoundLookupHoldsAtLeastOneRecord(): void
    {
        self::assertSame(['a', 'b'], DnsLookup::found(['a', 'b'])->records());

        $this->expectException(\InvalidArgumentException::class);

        DnsLookup::found([]);
    }

    /**
     * `contains()` matches a whole record byte for byte, never an empty value.
     *
     * @return void
     */
    public function testMatchesAWholeRecordExactly(): void
    {
        $found = DnsLookup::found(['first', 'token-value', '']);

        self::assertTrue($found->contains('token-value'));
        self::assertTrue($found->contains('first'));
        self::assertFalse($found->contains('TOKEN-VALUE'));
        self::assertFalse($found->contains('token'));
        self::assertFalse($found->contains('token-value '));
        self::assertFalse($found->contains(''));
        self::assertFalse(DnsLookup::absent()->contains('token-value'));
        self::assertFalse(DnsLookup::lookupFailed()->contains('token-value'));
    }

    /**
     * No dump, export, array cast or encoding shows a record.
     *
     * @return void
     */
    public function testNoRenderingShowsARecord(): void
    {
        $found = DnsLookup::found([self::RECORD]);

        self::assertStringNotContainsString(self::RECORD, print_r($found, true));
        self::assertStringNotContainsString(self::RECORD, var_export((array) $found, true));
        self::assertSame('{"status":"found"}', json_encode($found));
        self::assertSame(['status' => 'found', 'records' => '1 [redacted]'], $found->__debugInfo());
    }

    /**
     * A lookup refuses to be serialised.
     *
     * @return void
     */
    public function testRefusesToBeSerialized(): void
    {
        $this->expectException(\LogicException::class);

        serialize(DnsLookup::found([self::RECORD]));
    }

    /**
     * A lookup refuses to be unserialised.
     *
     * @return void
     */
    public function testRefusesToBeUnserialized(): void
    {
        $this->expectException(\LogicException::class);

        unserialize(sprintf('O:%d:"%s":0:{}', strlen(DnsLookup::class), DnsLookup::class));
    }
}
