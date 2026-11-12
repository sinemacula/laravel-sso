<?php

declare(strict_types = 1);

namespace Tests\Integration\Freshness;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Freshness\FreshnessCheck;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Integration tests of the default freshness contract in a booted application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessGate::class)]
#[CoversClass(RefusingFreshness::class)]
final class DefaultFreshnessRefusesTest extends TestCase
{
    use RunsConfigurationChecks;

    /**
     * The package is in use and its shipped freshness configuration passes.
     *
     * @return void
     */
    public function testThePackageIsInUseAndItsFreshnessConfigurationPasses(): void
    {
        self::assertTrue(config('sso.features.saml2'));
        self::assertSame([], $this->problemsOf(FreshnessCheck::class));
        self::assertInstanceOf(RefusingFreshness::class, $this->app?->make(Freshness::class));
    }

    /**
     * The default refuses every operation, alone and together, with or without
     * a caller.
     *
     * @return void
     */
    public function testTheDefaultRefusesEveryOperation(): void
    {
        $gate   = $this->gate();
        $caller = new Caller(new IdentityReference('App\Models\User', '42'), 'session-1');

        foreach (FreshnessOperation::cases() as $operation) {
            self::assertSame(FreshnessOutcome::STALE, $gate->check($operation, null), $operation->value);
            self::assertSame(FreshnessOutcome::STALE, $gate->check($operation, $caller), $operation->value);
            self::assertSame(FreshnessOutcome::STALE, $gate->checkAll([$operation], null), $operation->value);
        }

        self::assertSame(FreshnessOutcome::STALE, $gate->checkAll(FreshnessOperation::cases(), null));
    }

    /**
     * A fresh contract lets every operation through with its shipped maximum
     * age.
     *
     * @return void
     */
    public function testAFreshContractLetsEveryOperationThrough(): void
    {
        $freshness = FakeFreshness::fresh();

        $this->app?->instance(Freshness::class, $freshness);

        foreach (FreshnessOperation::cases() as $operation) {
            self::assertSame(FreshnessOutcome::FRESH, $this->gate()->check($operation, null), $operation->value);

            $freshness->assertAsked($operation, 300);
        }

        self::assertSame(FreshnessOutcome::FRESH, $this->gate()->checkAll(FreshnessOperation::cases(), null));

        $freshness->assertAskedExactly([...FreshnessOperation::cases(), ...FreshnessOperation::cases()]);
    }

    /**
     * Each request asks the contract bound when it is served.
     *
     * @return void
     */
    public function testEachRequestAsksTheContractBoundWhenItIsServed(): void
    {
        Route::post('/freshness/{operation}', static fn (FreshnessGate $gate, string $operation): JsonResponse => new JsonResponse([
            'outcome' => $gate->check(FreshnessOperation::from($operation), null)->value,
        ]));

        $this->postJson('/freshness/sso.connection.delete')->assertOk()->assertExactJson(['outcome' => 'stale']);

        $freshness = FakeFreshness::fresh();

        $this->app?->instance(Freshness::class, $freshness);

        $this->postJson('/freshness/sso.connection.delete')->assertOk()->assertExactJson(['outcome' => 'fresh']);

        $freshness->assertAskedExactly([FreshnessOperation::CONNECTION_DELETE]);
    }

    /**
     * Enable the package with a protocol, endpoints and an application, and
     * keep the shipped freshness block.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useThePackage();
    }

    /**
     * The gate the container builds.
     *
     * @return \SineMacula\Laravel\Sso\Freshness\FreshnessGate
     */
    private function gate(): FreshnessGate
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(FreshnessGate::class);
    }
}
