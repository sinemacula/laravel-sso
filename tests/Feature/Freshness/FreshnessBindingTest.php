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
 * Feature tests for the freshness contract's binding.
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
     * With nothing else bound, the container answers the refusing default.
     *
     * @return void
     */
    public function testTheRefusingContractIsTheDefault(): void
    {
        self::assertInstanceOf(RefusingFreshness::class, $this->freshness());

        foreach (FreshnessOperation::cases() as $operation) {
            self::assertSame(FreshnessOutcome::STALE, $this->freshness()->check($operation, 300, null));
        }
    }

    /**
     * The default is a singleton that survives forgetting the scoped instances.
     *
     * @return void
     */
    public function testTheDefaultIsASingleton(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app       = $this->app;
        $freshness = $this->freshness();

        self::assertTrue($app->isShared('sso.default:' . Freshness::class));
        self::assertSame($freshness, $this->freshness());

        $app->forgetScopedInstances();

        self::assertSame($freshness, $this->freshness());
    }

    /**
     * A contract bound before the provider registers is kept.
     *
     * @return void
     */
    public function testAContractBoundBeforeTheProviderRegistersIsKept(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app       = $this->app;
        $freshness = FakeFreshness::fresh();

        $app->instance(Freshness::class, $freshness);

        // Testbench registered the provider already; register it again.
        (new SsoServiceProvider($app))->register();

        self::assertSame($freshness, $this->freshness());
        self::assertSame(FreshnessOutcome::FRESH, $this->freshness()->check(FreshnessOperation::CONNECTION_TRUST, 300, null));
    }

    /**
     * A class bound before the provider registers is kept.
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
     * A contract bound after the default resolved replaces it for later
     * callers.
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
