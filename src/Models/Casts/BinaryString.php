<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models\Casts;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * A binary column held byte for byte (SSO-6.9): a subject is stored and read
 * back exactly as received, never trimmed, normalised or re-encoded, on every
 * engine.
 *
 * MySQL and SQLite take and give the bytes as a string. PostgreSQL gives a
 * `bytea` as a stream, which is read to its end; and it reads a string bound to
 * a `bytea` as text, interpreting backslashes and refusing invalid UTF-8, so a
 * value written there is bound as a stream, which Laravel binds as a large
 * object (`PDO::PARAM_LOB`), byte for byte.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Database\Eloquent\CastsAttributes<string, string>
 *
 * @internal
 */
final readonly class BinaryString implements CastsAttributes
{
    /**
     * The stored bytes, read to the end of a stream, or `null` when there are
     * none.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array<string, mixed>  $attributes
     * @return ?string
     *
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function get(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        unset($model, $attributes);

        if ($value === null || is_string($value)) {
            return $value;
        }

        if (!is_resource($value)) {
            throw new \UnexpectedValueException(sprintf('The [%s] column holds no bytes.', $key));
        }

        rewind($value);

        return (string) stream_get_contents($value);
    }

    /**
     * The bytes as the model's connection binds them: a stream on PostgreSQL, a
     * string on every other engine.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array<string, mixed>  $attributes
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function set(Model $model, string $key, mixed $value, array $attributes): mixed
    {
        unset($attributes);

        if ($value === null) {
            return null;
        }

        if (!is_string($value)) {
            throw new \InvalidArgumentException(sprintf('The [%s] column holds a string of bytes.', $key));
        }

        return $model->getConnection()->getDriverName() === 'pgsql' ? self::stream($value) : $value;
    }

    /**
     * A stream holding the bytes, rewound.
     *
     * @param  string  $bytes
     * @return resource
     *
     * @throws \UnexpectedValueException
     */
    private static function stream(string $bytes): mixed
    {
        $stream = fopen('php://memory', 'r+b');

        if ($stream === false) {
            throw new \UnexpectedValueException('A stream for binary bytes could not be opened.');
        }

        fwrite($stream, $bytes);
        rewind($stream);

        return $stream;
    }
}
