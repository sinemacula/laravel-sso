<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use Illuminate\Contracts\Database\ConcurrencyErrorDetector;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Exceptions\EnforcementPathChanged;
use Tests\TestCase;

/**
 * Unit tests for the exception that asks for an enforcement's transaction
 * again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnforcementPathChanged::class)]
final class EnforcementPathChangedTest extends TestCase
{
    /**
     * Laravel reads it as a serialisation failure.
     *
     * @return void
     */
    public function testIsAConcurrencyErrorToLaravel(): void
    {
        $exception = EnforcementPathChanged::retryWhole();

        self::assertInstanceOf(\PDOException::class, $exception);
        self::assertSame(40001, $exception->getCode());
        self::assertSame('A tenant\'s enforcement inheritance path changed before it was locked; retry the whole transaction.', $exception->getMessage());
        self::assertTrue(app(ConcurrencyErrorDetector::class)->causedByConcurrencyError($exception));
    }
}
