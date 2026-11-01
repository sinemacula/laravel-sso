<?php

declare(strict_types = 1);

namespace Tests\Feature\Freshness;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\TestCase;

/**
 * Feature tests for the freshness contract's binding in a booted application:
 * the refusing default, shared as a singleton across requests and jobs, a
 * contract the application bound before the package registers kept, and one
 * bound afterwards used instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoServiceProvider::class)]
#[CoversClass(RefusingFreshness::class)]
final class FreshnessBindingTest extends TestCase
{
    /**
     * With nothing else bound, the container answers the refusing default,
     * which refuses every operation.
     *
     * @return void
     */
    public function testTheRefusingContractIsTheDefault(): void
    {
        self::assertInstanceOf(RefusingFreshness::class, $this->freshness());

        foreach (FreshnessOperation::cases() as $operation) {
            self::assertSame(FreshnessOutcome::STALE, $this->freshness()->check($operation, 300));
        }
    }

    /**
     * The default holds nothing, so one instance is shared by every caller, and
     * is kept when the scoped instances are forgotten between requests or jobs,
     * as Octane and a queue worker forget them.
     *
     * @return void
     */
    public function testTheDefaultIsASingleton(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app       = $this->app;
        $freshness = $this->freshness();

        self::assertTrue($app->isShared(Freshness::class));
        self::assertSame($freshness, $this->freshness());

        $app->forgetScopedInstances();

        self::assertSame($freshness, $this->freshness());
    }

    /**
     * A contract the application bound before the package's provider registers
     * is kept, never replaced by the default.
     *
     * Testbench registers the provider before a test can bind anything, so the
     * test binds its contract and then runs the provider's registration again,
     * as a fresh application would.
     *
     * @return void
     */
    public function testAContractBoundBeforeTheProviderRegistersIsKept(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app       = $this->app;
        $freshness = FakeFreshness::fresh();

        $app->instance(Freshness::class, $freshness);

        (new SsoServiceProvider($app))->register();

        self::assertSame($freshness, $this->freshness());
        self::assertSame(FreshnessOutcome::FRESH, $this->freshness()->check(FreshnessOperation::CONNECTION_TRUST, 300));
    }

    /**
     * A contract the application binds as a class before the provider registers
     * is kept too, rather than only an instance.
     *
     * @return void
     */
    public function testAClassBoundBeforeTheProviderRegistersIsKept(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $app->singleton(Freshness::class, static fn (): FakeFreshness => FakeFreshness::fresh());

        (new SsoServiceProvider($app))->register();

        self::assertInstanceOf(FakeFreshness::class, $this->freshness());
    }

    /**
     * A contract bound once the package has registered, and after the default
     * was resolved, replaces the default for every later caller.
     *
     * @return void
     */
    public function testAContractBoundAfterwardsReplacesTheDefault(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        self::assertInstanceOf(RefusingFreshness::class, $this->freshness());

        $freshness = FakeFreshness::fresh();

        $app->instance(Freshness::class, $freshness);

        self::assertSame($freshness, $this->freshness());
    }

    /**
     * The freshness contract the container answers.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\Freshness
     */
    private function freshness(): Freshness
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(Freshness::class);
    }
}
