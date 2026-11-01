<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Database;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;

/**
 * Saves a model whose write carries a ciphertext, so a failed write never puts
 * the ciphertext in an exception message (SSO-2.5, SSO-11.9).
 *
 * Laravel's `QueryException` quotes the statement with its bindings in its
 * message, unless the connection sets `mask_bindings_in_exception_messages`,
 * and the driver's own message, which PostgreSQL's `DETAIL` can fill with the
 * failing row, is chained to it. Either reaches the application's log and error
 * reports. So when the save binds the ciphertext column (it is dirty and not
 * `null`), a `QueryException` becomes a `CiphertextWriteException`, a
 * `RuntimeException` with a fixed message, naming only the SQLSTATE, and chains
 * nothing. It still propagates as a server error (SSO-11.4), and the
 * transaction it unwinds still rolls back. A save that binds no ciphertext is
 * left as it is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CiphertextWrite
{
    /** @var string The SQLSTATE named when the failure gives none. */
    private const string UNKNOWN_STATE = 'unknown';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Save the model, refusing to echo the column's ciphertext should the write
     * fail.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $column
     * @param  string  $failure
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Database\CiphertextWriteException
     *
     * @phpstan-ignore throws.unusedType
     */
    public static function save(Model $model, string $column, string $failure): void
    {
        if (!$model->isDirty($column) || ($model->getAttributes()[$column] ?? null) === null) {
            $model->save();

            return;
        }

        try {
            $model->save();
            // Eloquent's save() declares no @throws, though a failed statement
            // throws a QueryException.
            // @phpstan-ignore catch.neverThrown
        } catch (QueryException $exception) {
            throw new CiphertextWriteException(sprintf('%s (SQLSTATE %s).', $failure, self::state($exception)));
        }
    }

    /**
     * The failure's SQLSTATE: five digits or upper-case letters, or `unknown`
     * when it gives none, so nothing else of the driver's report is named.
     *
     * @param  \Illuminate\Database\QueryException  $exception
     * @return string
     */
    private static function state(QueryException $exception): string
    {
        $state = $exception->errorInfo[0] ?? $exception->getCode();

        return is_string($state) && preg_match('/^[0-9A-Z]{5}$/', $state) === 1 ? $state : self::UNKNOWN_STATE;
    }
}
