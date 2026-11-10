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
 * Unit tests for the configuration checker: what it reports for each check, by
 * subject, that a check that does not apply is not run, that one that cannot be
 * resolved or is not a check is a problem, and that `assertValid()` fails with
 * every problem.
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
     * Each subject reports `null` when its check does not apply, `[]` when it
     * found nothing, and every problem it found otherwise, in the order the
     * checks are registered.
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
     * A check the container cannot build, and one it builds as something that
     * is not a check, are problems of their subject, never checks skipped.
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
     * `assertValid()` passes when nothing is found, a check that does not apply
     * included, and fails with every problem, each under its subject, when
     * something is.
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
