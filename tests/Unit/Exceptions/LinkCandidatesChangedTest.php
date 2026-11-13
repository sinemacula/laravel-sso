<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use Illuminate\Contracts\Database\ConcurrencyErrorDetector;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use Tests\TestCase;

/**
 * Unit tests for the exception that asks for the whole transaction again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkCandidatesChanged::class)]
final class LinkCandidatesChangedTest extends TestCase
{
    /**
     * Laravel reads it as a serialisation failure.
     *
     * @return void
     */
    public function testIsAConcurrencyErrorToLaravel(): void
    {
        $exception = LinkCandidatesChanged::retryWhole();

        self::assertInstanceOf(\PDOException::class, $exception);
        self::assertSame(40001, $exception->getCode());
        self::assertSame('An identity\'s verified domain links changed before they were locked; retry the whole transaction.', $exception->getMessage());
        self::assertTrue(app(ConcurrencyErrorDetector::class)->causedByConcurrencyError($exception));
    }

    /**
     * A caller's transaction with attempts runs again when it is thrown, from
     * its own level or a nested one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallersTransactionRetriesIt(): void
    {
        $database = DB::connection();
        $tries    = 0;

        $outcome = $database->transaction(static function (Connection $database) use (&$tries): string {

            $tries++;

            return $database->transaction(static fn (): string => $tries < 3 ? throw LinkCandidatesChanged::retryWhole() : 'done');
        }, 3);

        self::assertSame('done', $outcome);
        self::assertSame(3, $tries);
        self::assertSame(0, $database->transactionLevel());

        $tries = 0;

        $outcome = $database->transaction(static function () use (&$tries): string {

            $tries++;

            return $tries < 2 ? throw LinkCandidatesChanged::retryWhole() : 'done';
        }, 2);

        self::assertSame('done', $outcome);
        self::assertSame(2, $tries);
    }
}
