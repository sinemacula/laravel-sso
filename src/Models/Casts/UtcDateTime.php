<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models\Casts;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * A time column held as UTC seconds whatever the application timezone, since
 * the columns hold no offset and a DST fall-back would make values ambiguous.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Database\Eloquent\CastsAttributes<\Carbon\CarbonImmutable, \DateTimeInterface|int>
 *
 * @internal
 */
final readonly class UtcDateTime implements CastsAttributes
{
    /**
     * Constructor.
     *
     * @param  bool  $withoutObjectCaching
     */
    public function __construct(

        /** Always re-read, so a read is always the UTC `CarbonImmutable` from `get()`. */
        public bool $withoutObjectCaching = true,
    ) {}

    /**
     * The instant in the connection's date format, in UTC; stores bind with it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \DateTimeInterface|int  $instant
     * @return string
     */
    public static function format(Model $model, \DateTimeInterface|int $instant): string
    {
        $utc = is_int($instant) ? CarbonImmutable::createFromTimestamp($instant, 'UTC') : CarbonImmutable::instance($instant)->utc();

        return $utc->format($model->getDateFormat());
    }

    /**
     * The stored value as a UTC instant.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array<string, mixed>  $attributes
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function get(Model $model, string $key, mixed $value, array $attributes): ?CarbonImmutable
    {
        if ($value === null) {
            return null;
        }

        if (!is_string($value)) {
            throw new \UnexpectedValueException(sprintf('The stored value of `%s` is not a time.', $key));
        }

        return CarbonImmutable::parse($value, 'UTC');
    }

    /**
     * The instant or Unix time as stored.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array<string, mixed>  $attributes
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        if (!$value instanceof \DateTimeInterface && !is_int($value)) {
            throw new \InvalidArgumentException(sprintf('`%s` must be set to an instant or a Unix time.', $key));
        }

        return self::format($model, $value);
    }
}
