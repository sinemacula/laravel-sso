<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\DeadlockException;

/**
 * Runs work in a transaction that Laravel tries again on a concurrency failure,
 * a serialisation failure in a savepoint inside it included.
 *
 * Laravel throws a concurrency failure in a savepoint as a `DeadlockException`
 * with no SQLSTATE, which its detector then recognises by message alone: a
 * deadlock's, but not PostgreSQL's serialisation failure (SQLSTATE `40001`). So
 * inside the work, a `DeadlockException` whose chain of `DeadlockException`s
 * ends in a `40001` failure is rethrown as that failure, and Laravel retries it
 * within the attempts given. Anything else is rethrown as it is. The catch is
 * inside the transaction's callback, so an exception after the commit, an
 * after-commit listener's, never runs the work again.
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
     * Run the work in a transaction on the connection, tried up to the attempts
     * given in all.
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
            try {
                return $work($connection);
            } catch (DeadlockException $exception) {
                throw self::cause($exception);
            }
        }, $attempts);
    }

    /**
     * The serialisation failure at the end of the exception's chain of
     * `DeadlockException`s, or the exception itself when it ends in another.
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
