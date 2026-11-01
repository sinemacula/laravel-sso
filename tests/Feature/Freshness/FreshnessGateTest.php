<?php

declare(strict_types = 1);

namespace Tests\Feature\Freshness;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\TestCase;

/**
 * Feature tests for the freshness gate: it asks the bound contract with the
 * operation and its configured maximum age, resolves the contract and reads the
 * age on each call, fails closed on a malformed age before the contract is
 * asked, and asks about several operations once each, in order, stopping at the
 * first `stale`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessGate::class)]
final class FreshnessGateTest extends TestCase
{
    /**
     * The bound contract is asked with the operation and the age configured for
     * it, and its answer is the gate's.
     *
     * @return void
     */
    public function testAsksTheBoundContractWithTheConfiguredAge(): void
    {
        $freshness = $this->bind(FakeFreshness::fresh()->staleFor(FreshnessOperation::CONNECTION_DELETE));

        config()->set('sso.freshness.max_age_seconds.connection_trust', 120);

        self::assertSame(FreshnessOutcome::FRESH, $this->gate()->check(FreshnessOperation::CONNECTION_TRUST));
        self::assertSame(FreshnessOutcome::STALE, $this->gate()->check(FreshnessOperation::CONNECTION_DELETE));

        self::assertSame([
            ['operation' => FreshnessOperation::CONNECTION_TRUST, 'max_age_seconds' => 120],
            ['operation' => FreshnessOperation::CONNECTION_DELETE, 'max_age_seconds' => 300],
        ], $freshness->asked());
    }

    /**
     * Every operation is asked about with its own age.
     *
     * @return void
     */
    public function testAsksEveryOperationWithItsOwnAge(): void
    {
        $freshness = $this->bind(FakeFreshness::fresh());

        foreach (FreshnessOperation::cases() as $index => $operation) {
            config()->set('sso.freshness.max_age_seconds.' . $operation->configKey(), 100 + $index);
        }

        foreach (FreshnessOperation::cases() as $index => $operation) {
            self::assertSame(FreshnessOutcome::FRESH, $this->gate()->check($operation));

            $freshness->assertAsked($operation, 100 + $index);
        }

        $freshness->assertAskedExactly(FreshnessOperation::cases());
    }

    /**
     * The contract is resolved on each call, never held: a gate resolved under
     * the default refuses, and the same gate asks each contract bound later in
     * place of the one before.
     *
     * @return void
     */
    public function testResolvesTheContractOnEachCall(): void
    {
        $gate = $this->gate();

        self::assertSame(FreshnessOutcome::STALE, $gate->check(FreshnessOperation::LINK_CREATE));

        $first = $this->bind(FakeFreshness::fresh());

        self::assertSame(FreshnessOutcome::FRESH, $gate->check(FreshnessOperation::LINK_CREATE));

        $second = $this->bind(FakeFreshness::stale());

        self::assertSame(FreshnessOutcome::STALE, $gate->check(FreshnessOperation::LINK_REMOVE));

        $first->assertAskedExactly([FreshnessOperation::LINK_CREATE]);
        $second->assertAskedExactly([FreshnessOperation::LINK_REMOVE]);
    }

    /**
     * The age is read on each call, so a change between calls is the age the
     * next question is asked with.
     *
     * @return void
     */
    public function testReadsTheAgeOnEachCall(): void
    {
        $freshness = $this->bind(FakeFreshness::fresh());
        $gate      = $this->gate();

        config()->set('sso.freshness.max_age_seconds.keys_rotate', 600);

        $gate->check(FreshnessOperation::KEYS_ROTATE);

        config()->set('sso.freshness.max_age_seconds.keys_rotate', 60);

        $gate->check(FreshnessOperation::KEYS_ROTATE);

        self::assertSame([600, 60], array_column($freshness->asked(), 'max_age_seconds'));
    }

    /**
     * A malformed age throws, naming its key, before the contract is asked, so
     * a misconfigured requirement is never loosened to the contract's answer.
     *
     * @return void
     */
    public function testAMalformedAgeThrowsBeforeTheContractIsAsked(): void
    {
        $freshness = $this->bind(FakeFreshness::fresh());

        config()->set('sso.freshness.max_age_seconds.domain_claim', 0);

        try {
            $this->gate()->check(FreshnessOperation::DOMAIN_CLAIM);
            self::fail('A malformed age was asked with.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('sso.freshness.max_age_seconds.domain_claim must be an integer from 1 to 3600.', $exception->getMessage());
        }

        $freshness->assertNotAsked();
    }

    /**
     * `checkAll()` asks about each operation in the order given, and answers
     * `fresh` when every one is.
     *
     * @return void
     */
    public function testCheckAllAsksInTheOrderGiven(): void
    {
        $freshness  = $this->bind(FakeFreshness::fresh());
        $operations = [FreshnessOperation::CONNECTION_IDP_INITIATED, FreshnessOperation::CONNECTION_TRUST, FreshnessOperation::CONNECTION_ENABLE];

        config()->set('sso.freshness.max_age_seconds.connection_idp_initiated', 90);

        self::assertSame(FreshnessOutcome::FRESH, $this->gate()->checkAll($operations));

        $freshness->assertAskedExactly($operations);
        $freshness->assertAsked(FreshnessOperation::CONNECTION_IDP_INITIATED, 90);
    }

    /**
     * `checkAll()` asks about an operation given more than once only the first
     * time.
     *
     * @return void
     */
    public function testCheckAllAsksAboutEachOperationOnce(): void
    {
        $freshness = $this->bind(FakeFreshness::fresh());

        $answer = $this->gate()->checkAll([
            FreshnessOperation::CONNECTION_TRUST,
            FreshnessOperation::KEYS_ROTATE,
            FreshnessOperation::CONNECTION_TRUST,
            FreshnessOperation::KEYS_ROTATE,
            FreshnessOperation::CONNECTION_TRUST,
        ]);

        self::assertSame(FreshnessOutcome::FRESH, $answer);

        $freshness->assertAskedExactly([FreshnessOperation::CONNECTION_TRUST, FreshnessOperation::KEYS_ROTATE]);
    }

    /**
     * `checkAll()` answers `stale` at the first operation that is, and asks
     * about none after it.
     *
     * @return void
     */
    public function testCheckAllStopsAtTheFirstStale(): void
    {
        $freshness = $this->bind(FakeFreshness::fresh()->staleFor(FreshnessOperation::CONNECTION_IDP_INITIATED, FreshnessOperation::CONNECTION_ENABLE));

        $answer = $this->gate()->checkAll([
            FreshnessOperation::CONNECTION_TRUST,
            FreshnessOperation::CONNECTION_IDP_INITIATED,
            FreshnessOperation::CONNECTION_ENABLE,
            FreshnessOperation::KEYS_ROTATE,
        ]);

        self::assertSame(FreshnessOutcome::STALE, $answer);

        $freshness->assertAskedExactly([FreshnessOperation::CONNECTION_TRUST, FreshnessOperation::CONNECTION_IDP_INITIATED]);
    }

    /**
     * `checkAll()` with the first operation `stale` asks about nothing else.
     *
     * @return void
     */
    public function testCheckAllStopsAtAStaleFirstOperation(): void
    {
        $freshness = $this->bind(FakeFreshness::stale());

        self::assertSame(FreshnessOutcome::STALE, $this->gate()->checkAll(FreshnessOperation::cases()));

        $freshness->assertAskedExactly([FreshnessOperation::CONNECTION_TRUST]);
    }

    /**
     * `checkAll()` with no operation answers `fresh` and asks nothing, even of
     * the default, which would refuse anything it was asked.
     *
     * @return void
     */
    public function testCheckAllOfNoOperationIsFresh(): void
    {
        self::assertInstanceOf(RefusingFreshness::class, $this->app?->make(Freshness::class));
        self::assertSame(FreshnessOutcome::FRESH, $this->gate()->checkAll([]));

        $freshness = $this->bind(FakeFreshness::stale());

        self::assertSame(FreshnessOutcome::FRESH, $this->gate()->checkAll([]));

        $freshness->assertNotAsked();
    }

    /**
     * `checkAll()` throws at an operation whose age is malformed, having asked
     * about those before it and none from it on.
     *
     * @return void
     */
    public function testCheckAllThrowsAtAMalformedAge(): void
    {
        $freshness = $this->bind(FakeFreshness::fresh());

        config()->set('sso.freshness.max_age_seconds.domain_verify', 'five minutes');

        try {
            $this->gate()->checkAll([FreshnessOperation::DOMAIN_CLAIM, FreshnessOperation::DOMAIN_VERIFY, FreshnessOperation::DOMAIN_REMOVE]);
            self::fail('A malformed age was asked with.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('sso.freshness.max_age_seconds.domain_verify must be an integer from 1 to 3600.', $exception->getMessage());
        }

        $freshness->assertAskedExactly([FreshnessOperation::DOMAIN_CLAIM]);
    }

    /**
     * Bind the fake in place of the freshness contract.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeFreshness  $freshness
     * @return \SineMacula\Laravel\Sso\Testing\FakeFreshness
     */
    private function bind(FakeFreshness $freshness): FakeFreshness
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $app->instance(Freshness::class, $freshness);

        return $freshness;
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
