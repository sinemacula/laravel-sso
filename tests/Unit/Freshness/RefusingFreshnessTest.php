<?php

declare(strict_types = 1);

namespace Tests\Unit\Freshness;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Unit tests for the default freshness contract, which answers `stale`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefusingFreshness::class)]
final class RefusingFreshnessTest extends TestCase
{
    /** @var list<int> Maximum ages at, between and past the bounds. */
    private const array AGES = [1, 300, 3600, 0, -1, 86400, PHP_INT_MAX, PHP_INT_MIN];

    /**
     * The default is a freshness contract, so it binds in place of one.
     *
     * @return void
     */
    public function testIsAFreshnessContract(): void
    {
        self::assertInstanceOf(Freshness::class, new RefusingFreshness);
    }

    /**
     * Rows of `[operation]`: every freshness operation.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation}>
     */
    public static function provideOperations(): iterable
    {
        foreach (FreshnessOperation::cases() as $operation) {
            yield $operation->value => [$operation];
        }
    }

    /**
     * Each operation is refused at every maximum age, for any caller.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @return void
     */
    #[DataProvider('provideOperations')]
    public function testRefusesTheOperationAtEveryAge(FreshnessOperation $operation): void
    {
        $freshness = new RefusingFreshness;
        $caller    = new Caller(new IdentityReference('App\Models\User', '42'), 'session-1');

        foreach ([...self::AGES, ...self::AGES] as $age) {
            self::assertSame(FreshnessOutcome::STALE, $freshness->check($operation, $age, null), "{$operation->value} at {$age} seconds was not refused.");
            self::assertSame(FreshnessOutcome::STALE, $freshness->check($operation, $age, $caller), "{$operation->value} at {$age} seconds was not refused for a caller.");
        }
    }
}
