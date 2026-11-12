<?php

declare(strict_types = 1);

namespace Tests\Feature\Clock;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Clock\ClockCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for the `[clock]` configuration check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClockCheck::class)]
final class ClockCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /** @var string The problem a malformed skew is reported with. */
    private const string PROBLEM = 'sso.clock.skew_seconds must be an integer from 0 to 300.';

    /**
     * The skew is checked only while the package is in use.
     *
     * @return void
     */
    public function testAppliesOnlyWhileThePackageIsInUse(): void
    {
        config()->set('sso.clock.skew_seconds', 'sixty');

        self::assertNull($this->problemsOf(ClockCheck::class));

        $this->useThePackage();
        config()->set('sso.clock.skew_seconds', 60);

        self::assertSame([], $this->problemsOf(ClockCheck::class));
    }

    /**
     * A malformed protocol switch counts as in use, so the skew is checked.
     *
     * @return void
     */
    public function testAppliesOverAMalformedProtocolSwitch(): void
    {
        config()->set('sso.features.oidc', 'yes');
        config()->set('sso.clock.skew_seconds', 301);

        self::assertSame([self::PROBLEM], $this->problemsOf(ClockCheck::class));
    }

    /**
     * Rows of `[value, problems]`: skews and what each reports.
     *
     * @return iterable<string, array{0: mixed, 1: list<string>}>
     */
    public static function provideSkews(): iterable
    {
        yield from [
            'none'             => [0, []],
            'the ceiling'      => [300, []],
            'a digit string'   => ['120', []],
            'below none'       => [-1, [self::PROBLEM]],
            'past the ceiling' => [301, [self::PROBLEM]],
            'a decimal string' => ['1.5', [self::PROBLEM]],
            'null'             => [null, [self::PROBLEM]],
            'an empty string'  => ['', [self::PROBLEM]],
            'an array'         => [[60], [self::PROBLEM]],
        ];
    }

    /**
     * Each skew reports exactly its problems.
     *
     * @param  mixed  $value
     * @param  list<string>  $problems
     * @return void
     */
    #[DataProvider('provideSkews')]
    public function testReportsEachProblem(mixed $value, array $problems): void
    {
        $this->useThePackage();

        config()->set('sso.clock.skew_seconds', $value);

        self::assertSame($problems, $this->problemsOf(ClockCheck::class));
    }

    /**
     * A skew that is not configured at all takes the default and passes.
     *
     * @return void
     */
    public function testAnUnsetSkewPasses(): void
    {
        $this->useThePackage();

        config()->set('sso.clock', []);

        self::assertSame([], $this->problemsOf(ClockCheck::class));
    }
}
