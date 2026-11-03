<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Clock;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Clock\SystemClock;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FrozenClock;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/clock.md` (SSO-11.13, SSO-12.5), on the shared
 * example harness: the package's default clock following Laravel's time travel,
 * the application's own clock bound in a service provider in place of the
 * default, and a frozen clock bound and moved by a test. Each asserts the clock
 * the package reads by an authorisation request's ten-minute lifetime: a
 * response delivered at its end is refused with `request_expired`, and, by the
 * default and the frozen clock, one delivered a second short of it is handed
 * off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SystemClock::class)]
#[CoversClass(FrozenClock::class)]
final class ClockExampleTest extends ExampleTestCase
{
    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /**
     * Make the person.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->person = new IdentityReference('App\Models\User', 'person-1');
    }

    /**
     * With the harness's frozen clock unbound, the package reads its default,
     * which follows Laravel's clock: ten minutes of time travel expires the
     * request a flow started.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheDefaultClockFollowsLaravelsTime(): void
    {
        app()->forgetInstance(Clock::class);

        $this->freezeSecond();

        $provider     = $this->providerOnTheBoundClock();
        $connectionId = $this->makeOidcConnection($provider);

        self::assertInstanceOf(SystemClock::class, app(Clock::class));
        self::assertSame(now()->toIso8601ZuluString(), app(Clock::class)->now()->toIso8601ZuluString());

        // @snippet-start default-clock
        $start = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

        $this->travelTo(now()->addMinutes(10));

        $redirect = $this->respondAtProvider($provider, $connectionId, $start);

        self::assertSame(FailureReason::REQUEST_EXPIRED->value, $redirect->error);
        // @snippet-end default-clock
        $this->travelBack();
    }

    /**
     * A second short of the request's lifetime by Laravel's clock, the default
     * clock still consumes it and the flow is handed off.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheDefaultClockConsumesARequestWithinItsLifetime(): void
    {
        app()->forgetInstance(Clock::class);

        $this->freezeSecond();

        $provider     = $this->providerOnTheBoundClock();
        $connectionId = $this->makeOidcConnection($provider);

        $start = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

        $this->travelTo(now()->addSeconds(599));

        self::assertTrue($this->respondAtProvider($provider, $connectionId, $start)->hasCode());

        $this->travelBack();
    }

    /**
     * The application's own clock, bound by its service provider after the
     * package's, replaces the harness's frozen clock as the one shared clock
     * the package reads: it follows Laravel's time, so ten minutes of time
     * travel expires the request while the frozen clock has not moved.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheApplicationsOwnClockReplacesTheDefault(): void
    {
        app()->register(AppServiceProvider::class);

        self::assertInstanceOf(UtcClock::class, app(Clock::class));
        self::assertSame(app(Clock::class), app(Clock::class));

        $this->freezeSecond();

        $provider     = $this->providerOnTheBoundClock();
        $connectionId = $this->makeOidcConnection($provider);

        $start = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

        $this->travelTo(now()->addMinutes(10));

        self::assertSame(FailureReason::REQUEST_EXPIRED->value, $this->respondAtProvider($provider, $connectionId, $start)->error);
        self::assertSame(self::NOW, $this->clock->now()->toIso8601ZuluString());

        $this->travelBack();
    }

    /**
     * A frozen clock bound in place of the package's moves only when the test
     * moves it, backwards as well as forwards: a request started at its instant
     * expires when it has moved ten minutes on, and one moved a second short of
     * that is handed off.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFrozenClockMovesOnlyWhenTheTestMovesIt(): void
    {
        // @snippet-start frozen-clock-bound
        $clock = new FrozenClock('2026-10-31T12:00:00Z');

        $this->instance(Clock::class, $clock);

        $clock->advance(61);

        self::assertSame('2026-10-31T12:01:01Z', app(Clock::class)->now()->toIso8601ZuluString());

        $clock->advance(-120);

        self::assertSame('2026-10-31T11:59:01Z', app(Clock::class)->now()->toIso8601ZuluString());

        $clock->setTo('2026-11-01T00:00:00Z');

        self::assertSame('2026-11-01T00:00:00Z', app(Clock::class)->now()->toIso8601ZuluString());
        // @snippet-end frozen-clock-bound
        $provider     = $this->providerOnTheBoundClock();
        $connectionId = $this->makeOidcConnection($provider);

        $expired = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

        $clock->advance(600);

        self::assertSame(FailureReason::REQUEST_EXPIRED->value, $this->respondAtProvider($provider, $connectionId, $expired)->error);

        $start = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

        $clock->advance(599);

        self::assertTrue($this->respondAtProvider($provider, $connectionId, $start)->hasCode());
    }

    /**
     * Make the provider, reading the clock now bound; the link store is bound
     * afresh, since the one the harness bound was given the clock bound before.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider
     */
    private function providerOnTheBoundClock(): FakeOpenIdProvider
    {
        $this->instance(Linker::class, app(LinkStore::class));

        return new FakeOpenIdProvider(clock: app(Clock::class));
    }
}
