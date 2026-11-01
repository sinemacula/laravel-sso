<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Exceptions\InvalidConfigurationException;

/**
 * Unit tests for the boot check's exception: a logic error that lists every
 * problem in its message and keeps them for a caller to read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidConfigurationException::class)]
final class InvalidConfigurationExceptionTest extends TestCase
{
    /**
     * The exception names every problem, one per line, points at `sso:check`,
     * and keeps the problems.
     *
     * @return void
     */
    public function testListsEveryProblem(): void
    {
        $exception = InvalidConfigurationException::withProblems(['[storage] first', '[endpoints] second']);

        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertSame("laravel-sso is misconfigured; `php artisan sso:check` lists the same problems:\n- [storage] first\n- [endpoints] second", $exception->getMessage());
        self::assertSame(['[storage] first', '[endpoints] second'], $exception->problems());
    }

    /**
     * An exception built directly holds no problems.
     *
     * @return void
     */
    public function testAnExceptionBuiltDirectlyHoldsNoProblems(): void
    {
        self::assertSame([], (new InvalidConfigurationException('message'))->problems());
    }
}
