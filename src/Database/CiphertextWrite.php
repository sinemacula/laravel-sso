<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Database;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;

/**
 * Saves a model whose write carries a ciphertext without leaking it into an
 * exception.
 *
 * `QueryException` quotes the bindings, and PostgreSQL's chained `DETAIL` can
 * hold the row, so the failure is replaced by one naming only the SQLSTATE.
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
     * Save the model, keeping the column's ciphertext out of any failure.
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
            // Eloquent's save() declares no @throws.
            // @phpstan-ignore catch.neverThrown
        } catch (QueryException $exception) {
            throw new CiphertextWriteException(sprintf('%s (SQLSTATE %s).', $failure, self::state($exception)));
        }
    }

    /**
     * The failure's SQLSTATE, or `unknown` when it is not one.
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
