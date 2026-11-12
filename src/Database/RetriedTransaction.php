<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\DeadlockException;

/**
 * Runs work in a transaction Laravel retries on any concurrency failure,
 * including one raised in a nested savepoint.
 *
 * Laravel wraps a savepoint's failure in a `DeadlockException` with no
 * SQLSTATE, hiding PostgreSQL's `40001`, so the cause is unwrapped to retry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RetriedTransaction
{
    /** @var string The SQLSTATE of a serialisation failure. */
    private const string SERIALIZATION_FAILURE = '40001';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Run the work in a transaction, tried at most `$attempts` times in all.
     *
     * @template TResult
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \Closure(\Illuminate\Database\Connection): TResult  $work
     * @param  int<1, max>  $attempts
     * @return TResult
     *
     * @throws \Throwable
     */
    public static function run(Connection $connection, \Closure $work, int $attempts): mixed
    {
        return $connection->transaction(static function (Connection $connection) use ($work): mixed {
            // Inside the callback, so an after-commit failure never reruns it.
            try {
                return $work($connection);
            } catch (DeadlockException $exception) {
                throw self::cause($exception);
            }
        }, $attempts);
    }

    /**
     * The serialisation failure the `DeadlockException` chain ends in, or the
     * exception itself.
     *
     * @param  \Illuminate\Database\DeadlockException  $exception
     * @return \Throwable
     */
    private static function cause(DeadlockException $exception): \Throwable
    {
        $cause = $exception->getPrevious();

        while ($cause instanceof DeadlockException) {
            $cause = $cause->getPrevious();
        }

        return $cause instanceof \PDOException && $cause->getCode() === self::SERIALIZATION_FAILURE ? $cause : $exception;
    }
}
