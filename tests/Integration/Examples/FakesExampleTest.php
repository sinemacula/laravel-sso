<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Metadata\DiscoveryImporter;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FrozenClock;

/**
 * The worked examples of the fakes' own behaviour in the testing guide
 * (SSO-12.4): the fake fetcher and the fake DNS resolver throw on a request
 * nobody gave them an answer for, the frozen clock holds its instant whatever
 * Laravel's time travel does, and the fake freshness contract answers what the
 * test tells it and records what it was asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeFetcher::class)]
#[CoversClass(FakeDnsResolver::class)]
#[CoversClass(FrozenClock::class)]
#[CoversClass(FakeFreshness::class)]
final class FakesExampleTest extends ExampleTestCase
{
    /**
     * A discovery document nobody told the fake fetcher to answer is a
     * `LogicException` naming its URL, never a quiet failure.
     *
     * @return void
     */
    public function testTheFakeFetcherRefusesARequestNobodyExpected(): void
    {
        // @snippet-start fetcher-unexpected
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('FakeFetcher has no response for [https://unknown.example.test/.well-known/openid-configuration].');

        app(DiscoveryImporter::class)->import(self::TENANT, 'https://unknown.example.test');
        // @snippet-end fetcher-unexpected
    }

    /**
     * A record nobody told the fake resolver to answer is a `LogicException`
     * naming it, never a quiet failure.
     *
     * @return void
     */
    public function testTheFakeResolverRefusesALookupNobodyExpected(): void
    {
        $connectionId = $this->makeOidcConnection(new FakeOpenIdProvider(clock: $this->clock));

        // @snippet-start resolver-unexpected
        app(DomainService::class)->claim(self::TENANT, $connectionId, 'example.com');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The fake DNS resolver has no answer for [_sso-verification.example.com].');

        app(DomainService::class)->verify(self::TENANT, $connectionId, 'example.com');
        // @snippet-end resolver-unexpected
    }

    /**
     * Laravel's time travel moves Laravel's clock, never the frozen clock the
     * package reads; the frozen clock moves only when the test moves it.
     *
     * @return void
     */
    public function testTheFrozenClockIgnoresLaravelsTimeTravel(): void
    {
        // @snippet-start frozen-clock
        $this->travelTo(CarbonImmutable::parse('2027-01-01T00:00:00Z'));

        self::assertSame('2027-01-01T00:00:00Z', CarbonImmutable::now('UTC')->toIso8601ZuluString());
        self::assertSame('2026-11-01T09:30:00Z', $this->clock->now()->toIso8601ZuluString());

        $this->clock->advance(90);

        self::assertSame('2026-11-01T09:31:30Z', $this->clock->now()->toIso8601ZuluString());

        $this->clock->setTo('2026-11-02T08:00:00Z');

        self::assertSame('2026-11-02T08:00:00Z', $this->clock->now()->toIso8601ZuluString());
        // @snippet-end frozen-clock
        $this->travelBack();
    }

    /**
     * The fake freshness contract answers `stale` for the operations it is told
     * to, refusing a `link` with `freshness_required`, and `fresh` for any
     * other; it records each operation it was asked about, with the maximum
     * age.
     *
     * @return void
     */
    public function testFakeFreshnessAnswersWhatTheTestSays(): void
    {
        $connectionId = $this->makeOidcConnection(new FakeOpenIdProvider(clock: $this->clock));
        $person       = new IdentityReference('App\Models\User', 'person-1');

        // @snippet-start fake-freshness
        $this->freshness->staleFor(FreshnessOperation::LINK_CREATE);

        $refused = $this->startFlow(Purpose::LINK, $connectionId, $person);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $refused->reason);
        $this->freshness->assertAsked(FreshnessOperation::LINK_CREATE, 300);

        self::assertTrue($this->startFlow(Purpose::SIGN_IN, $connectionId)->isStarted());
        // @snippet-end fake-freshness
    }
}
