<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Domains\DnsLookup;
use SineMacula\Laravel\Sso\Domains\DomainSummary;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;

/**
 * Unit tests for the fake DNS resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeDnsResolver::class)]
final class FakeDnsResolverTest extends TestCase
{
    /**
     * Each name is answered as given, whatever its case or trailing dot, and a
     * later answer replaces an earlier one.
     *
     * @return void
     */
    public function testAnswersEachNameAsGiven(): void
    {
        $dns = (new FakeDnsResolver)
            ->found('a.example.com', 'one', 'two')
            ->absent('b.example.com')
            ->failing('c.example.com')
            ->found('d.example.com', 'first')
            ->absent('d.example.com');

        self::assertSame(['one', 'two'], $dns->txt('A.Example.COM.')->records());
        self::assertTrue($dns->txt('b.example.com')->isAbsent());
        self::assertTrue($dns->txt('c.example.com')->isLookupFailed());
        self::assertTrue($dns->txt('d.example.com')->isAbsent());
        self::assertSame(['A.Example.COM.', 'b.example.com', 'c.example.com', 'd.example.com'], $dns->lookups());
    }

    /**
     * A closure answer is built from the name on each lookup.
     *
     * @return void
     */
    public function testAClosureAnswerIsBuiltOnEachLookup(): void
    {
        $count = 0;
        $dns   = (new FakeDnsResolver)->answer('example.com', static function (string $name) use (&$count): DnsLookup {
            $count++;

            return $count === 1 ? DnsLookup::found([$name]) : DnsLookup::lookupFailed();
        });

        self::assertSame(['example.com'], $dns->txt('example.com')->records());
        self::assertTrue($dns->txt('example.com')->isLookupFailed());
    }

    /**
     * A claimed domain's record is published with its token.
     *
     * @return void
     */
    public function testPublishesAClaimedDomainsRecord(): void
    {
        $summary = new DomainSummary(
            id: '01jbexampledomain000000000',
            connectionId: '01jbexampleconnection00000',
            domain: 'example.com',
            state: DomainState::PENDING,
            recordName: '_sso-verification.example.com',
            verificationToken: 'the-token',
            claimedAt: CarbonImmutable::parse('2026-11-01T09:30:00Z'),
        );

        $dns = (new FakeDnsResolver)->publishes($summary);

        self::assertTrue($dns->txt('_sso-verification.example.com')->contains('the-token'));
    }

    /**
     * A lookup of a name with no answer throws, naming the name.
     *
     * @return void
     */
    public function testAStrayLookupFailsLoudly(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The fake DNS resolver has no answer for [stray.example.com].');

        (new FakeDnsResolver)->txt('stray.example.com');
    }

    /**
     * The assertions pass on what was looked up and fail otherwise.
     *
     * @return void
     */
    public function testAssertsWhatWasLookedUp(): void
    {
        $dns = (new FakeDnsResolver)->absent('example.com');

        $dns->assertNothingLookedUp();

        $dns->txt('example.com');
        $dns->txt('EXAMPLE.com.');

        $dns->assertLookedUp('example.com');
        $dns->assertLookedUp('example.com', 2);

        $this->expectException(AssertionFailedError::class);

        $dns->assertLookedUp('example.com', 1);
    }

    /**
     * Asserting a lookup that was not made fails, as does asserting nothing was
     * looked up after one was.
     *
     * @return void
     */
    public function testFailsOnALookupNotMade(): void
    {
        $dns = (new FakeDnsResolver)->absent('example.com');

        try {
            $dns->assertLookedUp('example.com');
            self::fail('The assertion passed.');
        } catch (AssertionFailedError $error) {
            self::assertStringContainsString('Expected [example.com] to be looked up', $error->getMessage());
        }

        $dns->txt('example.com');

        $this->expectException(AssertionFailedError::class);

        $dns->assertNothingLookedUp();
    }
}
