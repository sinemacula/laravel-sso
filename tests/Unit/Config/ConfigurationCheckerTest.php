<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\Exceptions\InvalidConfigurationException;
use Tests\Unit\Config\Fixtures\FailingCheck;
use Tests\Unit\Config\Fixtures\InapplicableCheck;
use Tests\Unit\Config\Fixtures\PassingCheck;

/**
 * Unit tests for the configuration checker.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigurationChecker::class)]
final class ConfigurationCheckerTest extends TestCase
{
    /**
     * Each subject reports `null` if inapplicable, else its problems in order.
     *
     * @return void
     */
    public function testReportsEachSubject(): void
    {
        $checker = new ConfigurationChecker(new Container, [
            'passing'      => PassingCheck::class,
            'inapplicable' => InapplicableCheck::class,
            'failing'      => FailingCheck::class,
        ]);

        self::assertSame([
            'passing'      => [],
            'inapplicable' => null,
            'failing'      => ['`sso.example.first` must be set.', 'The PHP extension `example` is not loaded.'],
        ], $checker->report());

        self::assertSame([
            '[failing] `sso.example.first` must be set.',
            '[failing] The PHP extension `example` is not loaded.',
        ], $checker->problems());
    }

    /**
     * A check that cannot be built, or is not a check, is a problem.
     *
     * @return void
     */
    public function testACheckThatCannotBeUsedIsAProblem(): void
    {
        $container = new Container;

        $container->bind(PassingCheck::class, static fn (): \stdClass => new \stdClass);

        $checker = new ConfigurationChecker($container, [
            'missing'   => ConfigurationCheck::class,
            'not_check' => PassingCheck::class,
        ]);

        $report = $checker->report();

        self::assertSame(['Target [SineMacula\Laravel\Sso\Contracts\ConfigurationCheck] is not instantiable.'], $report['missing']);
        self::assertSame(['[Tests\Unit\Config\Fixtures\PassingCheck] is not a SineMacula\Laravel\Sso\Contracts\ConfigurationCheck.'], $report['not_check']);
    }

    /**
     * `assertValid()` fails with every problem under its subject.
     *
     * @return void
     */
    public function testAssertValidFailsWithEveryProblem(): void
    {
        (new ConfigurationChecker(new Container, ['passing' => PassingCheck::class, 'inapplicable' => InapplicableCheck::class]))->assertValid();

        try {
            (new ConfigurationChecker(new Container, ['passing' => PassingCheck::class, 'failing' => FailingCheck::class]))->assertValid();

            self::fail('Expected the configuration to be refused.');
        } catch (InvalidConfigurationException $exception) {
            self::assertSame([
                '[failing] `sso.example.first` must be set.',
                '[failing] The PHP extension `example` is not loaded.',
            ], $exception->problems());

            self::assertSame(
                "laravel-sso is misconfigured; `php artisan sso:check` lists the same problems:\n"
                . "- [failing] `sso.example.first` must be set.\n"
                . '- [failing] The PHP extension `example` is not loaded.',
                $exception->getMessage(),
            );
        }
    }

    /**
     * No check is registered, so nothing is reported and nothing fails.
     *
     * @return void
     */
    public function testNoChecksReportNothing(): void
    {
        $checker = new ConfigurationChecker(new Container, []);

        self::assertSame([], $checker->report());

        $checker->assertValid();
    }
}
