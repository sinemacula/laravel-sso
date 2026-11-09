<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;

/**
 * Unit tests for the fake freshness contract: it answers `fresh` unless built
 * `stale` or told which operations alone are, records every question in order
 * with its maximum age, holds both per instance, and its assertions pass and
 * fail as they say.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeFreshness::class)]
final class FakeFreshnessTest extends TestCase
{
    /**
     * The fake is a freshness contract, so it binds in place of the package's.
     *
     * @return void
     */
    public function testIsAFreshnessContract(): void
    {
        self::assertInstanceOf(Freshness::class, new FakeFreshness);
    }

    /**
     * Built with no outcome, or with `fresh()`, it answers `fresh` for every
     * operation; built with `stale()`, or the `stale` outcome, it answers
     * `stale` for every one.
     *
     * @return void
     */
    public function testAnswersTheOutcomeItWasBuiltWith(): void
    {
        foreach (FreshnessOperation::cases() as $operation) {
            self::assertSame(FreshnessOutcome::FRESH, (new FakeFreshness)->check($operation, 300, null));
            self::assertSame(FreshnessOutcome::FRESH, FakeFreshness::fresh()->check($operation, 300, null));
            self::assertSame(FreshnessOutcome::STALE, FakeFreshness::stale()->check($operation, 300, null));
            self::assertSame(FreshnessOutcome::STALE, (new FakeFreshness(FreshnessOutcome::STALE))->check($operation, 300, null));
        }
    }

    /**
     * `fresh()` and `stale()` build a new fake each time.
     *
     * @return void
     */
    public function testEachNamedConstructorBuildsANewFake(): void
    {
        self::assertNotSame(FakeFreshness::fresh(), FakeFreshness::fresh());
        self::assertNotSame(FakeFreshness::stale(), FakeFreshness::stale());
    }

    /**
     * After `staleFor()`, only the operations given answer `stale`, every other
     * `fresh`, and the fake is returned for chaining.
     *
     * @return void
     */
    public function testStaleForRefusesOnlyTheOperationsGiven(): void
    {
        $freshness = new FakeFreshness;

        self::assertSame($freshness, $freshness->staleFor(FreshnessOperation::CONNECTION_DELETE, FreshnessOperation::LINK_REMOVE));

        foreach (FreshnessOperation::cases() as $operation) {
            $expected = in_array($operation, [FreshnessOperation::CONNECTION_DELETE, FreshnessOperation::LINK_REMOVE], true)
                ? FreshnessOutcome::STALE
                : FreshnessOutcome::FRESH;

            self::assertSame($expected, $freshness->check($operation, 300, null), $operation->value);
        }
    }

    /**
     * `staleFor()` on a fake built `stale` still refuses only the operations
     * given.
     *
     * @return void
     */
    public function testStaleForOverridesAStaleFake(): void
    {
        $freshness = FakeFreshness::stale()->staleFor(FreshnessOperation::KEYS_ROTATE);

        self::assertSame(FreshnessOutcome::STALE, $freshness->check(FreshnessOperation::KEYS_ROTATE, 300, null));
        self::assertSame(FreshnessOutcome::FRESH, $freshness->check(FreshnessOperation::CONNECTION_TRUST, 300, null));
    }

    /**
     * A later `staleFor()` adds to the operations an earlier one gave, and an
     * operation given twice is still refused.
     *
     * @return void
     */
    public function testStaleForAddsToAnEarlierCall(): void
    {
        $freshness = FakeFreshness::fresh()
            ->staleFor(FreshnessOperation::DOMAIN_CLAIM)
            ->staleFor(FreshnessOperation::DOMAIN_VERIFY, FreshnessOperation::DOMAIN_CLAIM);

        self::assertSame(FreshnessOutcome::STALE, $freshness->check(FreshnessOperation::DOMAIN_CLAIM, 300, null));
        self::assertSame(FreshnessOutcome::STALE, $freshness->check(FreshnessOperation::DOMAIN_VERIFY, 300, null));
        self::assertSame(FreshnessOutcome::FRESH, $freshness->check(FreshnessOperation::DOMAIN_REMOVE, 300, null));
    }

    /**
     * `staleFor()` with no operation leaves every operation `fresh`.
     *
     * @return void
     */
    public function testStaleForWithNoOperationRefusesNone(): void
    {
        $freshness = FakeFreshness::stale()->staleFor();

        foreach (FreshnessOperation::cases() as $operation) {
            self::assertSame(FreshnessOutcome::FRESH, $freshness->check($operation, 300, null));
        }
    }

    /**
     * Every question is recorded with its maximum age and its caller, as given
     * or none, in order, a repeat and a refused one included, and nothing
     * before the first.
     *
     * @return void
     */
    public function testRecordsEveryQuestionInOrder(): void
    {
        $freshness = FakeFreshness::fresh()->staleFor(FreshnessOperation::LINK_CREATE);
        $caller    = new Caller(new IdentityReference('App\Models\User', '42'), 'session-1');

        self::assertSame([], $freshness->asked());

        $freshness->check(FreshnessOperation::CONNECTION_TRUST, 120, $caller);
        $freshness->check(FreshnessOperation::LINK_CREATE, 60, null);
        $freshness->check(FreshnessOperation::CONNECTION_TRUST, 3600, $caller);

        self::assertSame([
            ['operation' => FreshnessOperation::CONNECTION_TRUST, 'max_age_seconds' => 120, 'caller' => $caller],
            ['operation' => FreshnessOperation::LINK_CREATE, 'max_age_seconds' => 60, 'caller' => null],
            ['operation' => FreshnessOperation::CONNECTION_TRUST, 'max_age_seconds' => 3600, 'caller' => $caller],
        ], $freshness->asked());
    }

    /**
     * Each fake holds its own answers and questions: nothing one is told or
     * asked reaches another.
     *
     * @return void
     */
    public function testHoldsItsStatePerInstance(): void
    {
        $first  = FakeFreshness::fresh()->staleFor(FreshnessOperation::CONNECTION_ENABLE);
        $second = FakeFreshness::fresh();

        $first->check(FreshnessOperation::CONNECTION_ENABLE, 300, null);

        self::assertSame(FreshnessOutcome::FRESH, $second->check(FreshnessOperation::CONNECTION_ENABLE, 300, null));
        self::assertCount(1, $first->asked());
        self::assertSame([['operation' => FreshnessOperation::CONNECTION_ENABLE, 'max_age_seconds' => 300, 'caller' => null]], $second->asked());
    }

    /**
     * `assertAsked()` passes for an operation asked about, with or without its
     * maximum age.
     *
     * @return void
     */
    public function testAssertAskedPassesForAnOperationAsked(): void
    {
        $freshness = FakeFreshness::stale();

        $freshness->check(FreshnessOperation::CONNECTION_TRUST, 120, null);
        $freshness->check(FreshnessOperation::CONNECTION_TRUST, 300, null);

        $freshness->assertAsked(FreshnessOperation::CONNECTION_TRUST);
        $freshness->assertAsked(FreshnessOperation::CONNECTION_TRUST, 120);
        $freshness->assertAsked(FreshnessOperation::CONNECTION_TRUST, 300);
    }

    /**
     * `assertAsked()` fails for an operation not asked about, naming it.
     *
     * @return void
     */
    public function testAssertAskedFailsForAnotherOperation(): void
    {
        $freshness = FakeFreshness::fresh();

        $freshness->check(FreshnessOperation::CONNECTION_TRUST, 300, null);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Expected [sso.connection.delete] to be asked; it was not.');

        $freshness->assertAsked(FreshnessOperation::CONNECTION_DELETE);
    }

    /**
     * `assertAsked()` fails for an operation asked about with another maximum
     * age, naming the age expected.
     *
     * @return void
     */
    public function testAssertAskedFailsForAnotherAge(): void
    {
        $freshness = FakeFreshness::fresh();

        $freshness->check(FreshnessOperation::KEYS_ROTATE, 300, null);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Expected [sso.keys.rotate with a maximum age of 60 seconds] to be asked; it was not.');

        $freshness->assertAsked(FreshnessOperation::KEYS_ROTATE, 60);
    }

    /**
     * `assertAsked()` fails when nothing was asked.
     *
     * @return void
     */
    public function testAssertAskedFailsWhenNothingWasAsked(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Expected [sso.link.create] to be asked; it was not.');

        FakeFreshness::fresh()->assertAsked(FreshnessOperation::LINK_CREATE);
    }

    /**
     * `assertAskedExactly()` passes for the operations asked about, in order, a
     * repeat included, and for none before any question.
     *
     * @return void
     */
    public function testAssertAskedExactlyPassesForTheOperationsInOrder(): void
    {
        $freshness = FakeFreshness::fresh();

        $freshness->assertAskedExactly([]);

        $freshness->check(FreshnessOperation::CONNECTION_TRUST, 300, null);
        $freshness->check(FreshnessOperation::CONNECTION_IDP_INITIATED, 60, null);
        $freshness->check(FreshnessOperation::CONNECTION_TRUST, 300, null);

        $freshness->assertAskedExactly([FreshnessOperation::CONNECTION_TRUST, FreshnessOperation::CONNECTION_IDP_INITIATED, FreshnessOperation::CONNECTION_TRUST]);
    }

    /**
     * `assertAskedExactly()` fails for the right operations in another order.
     *
     * @return void
     */
    public function testAssertAskedExactlyFailsForAnotherOrder(): void
    {
        $freshness = FakeFreshness::fresh();

        $freshness->check(FreshnessOperation::DOMAIN_CLAIM, 300, null);
        $freshness->check(FreshnessOperation::DOMAIN_VERIFY, 300, null);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Expected exactly [sso.domain.verify, sso.domain.claim] to be asked, in order.');

        $freshness->assertAskedExactly([FreshnessOperation::DOMAIN_VERIFY, FreshnessOperation::DOMAIN_CLAIM]);
    }

    /**
     * `assertAskedExactly()` fails when an operation was asked about that is
     * not given.
     *
     * @return void
     */
    public function testAssertAskedExactlyFailsForAnExtraQuestion(): void
    {
        $freshness = FakeFreshness::fresh();

        $freshness->check(FreshnessOperation::ENFORCEMENT_UPDATE, 300, null);
        $freshness->check(FreshnessOperation::ENFORCEMENT_UPDATE, 300, null);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Expected exactly [sso.enforcement.update] to be asked, in order.');

        $freshness->assertAskedExactly([FreshnessOperation::ENFORCEMENT_UPDATE]);
    }

    /**
     * `assertAskedExactly()` fails when an operation given was not asked about.
     *
     * @return void
     */
    public function testAssertAskedExactlyFailsForAMissingQuestion(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Expected exactly [sso.link.remove] to be asked, in order.');

        FakeFreshness::fresh()->assertAskedExactly([FreshnessOperation::LINK_REMOVE]);
    }

    /**
     * `assertAskedExactly([])` fails once anything was asked.
     *
     * @return void
     */
    public function testAssertAskedExactlyNothingFailsAfterAQuestion(): void
    {
        $freshness = FakeFreshness::stale();

        $freshness->check(FreshnessOperation::LINK_REMOVE, 300, null);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Expected exactly [] to be asked, in order.');

        $freshness->assertAskedExactly([]);
    }

    /**
     * `assertNotAsked()` passes before any question.
     *
     * @return void
     */
    public function testAssertNotAskedPassesBeforeAnyQuestion(): void
    {
        FakeFreshness::stale()->assertNotAsked();
    }

    /**
     * `assertNotAsked()` fails after any question, a refused one included.
     *
     * @return void
     */
    public function testAssertNotAskedFailsAfterAQuestion(): void
    {
        $freshness = FakeFreshness::stale();

        $freshness->check(FreshnessOperation::CONNECTION_ENABLE, 300, null);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Expected nothing to be asked.');

        $freshness->assertNotAsked();
    }

    /**
     * `assertNotAsked()` with an operation passes when only others were asked
     * about.
     *
     * @return void
     */
    public function testAssertNotAskedAnOperationPassesWhenOnlyOthersWereAsked(): void
    {
        $freshness = FakeFreshness::fresh();

        $freshness->assertNotAsked(FreshnessOperation::CONNECTION_DELETE);

        $freshness->check(FreshnessOperation::CONNECTION_ENABLE, 300, null);

        $freshness->assertNotAsked(FreshnessOperation::CONNECTION_DELETE);
    }

    /**
     * `assertNotAsked()` with an operation fails once it was asked about,
     * naming it.
     *
     * @return void
     */
    public function testAssertNotAskedAnOperationFailsOnceItWasAsked(): void
    {
        $freshness = FakeFreshness::fresh();

        $freshness->check(FreshnessOperation::CONNECTION_ENABLE, 300, null);
        $freshness->check(FreshnessOperation::CONNECTION_DELETE, 300, null);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Expected [sso.connection.delete] not to be asked; it was.');

        $freshness->assertNotAsked(FreshnessOperation::CONNECTION_DELETE);
    }
}
