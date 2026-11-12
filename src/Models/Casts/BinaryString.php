<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models\Casts;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * A binary column stored and read back byte for byte on every engine.
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
     * The stored bytes; PostgreSQL returns a `bytea` as a stream.
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
     * A stream on PostgreSQL, which reads a string bound to a `bytea` as text.
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
