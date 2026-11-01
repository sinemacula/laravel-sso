<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models\Casts;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * A time column held as UTC wall-clock seconds, whatever the application
 * timezone: written in UTC, and read back as the instant it names in UTC.
 *
 * The package's time columns hold no offset. Written in a timezone with
 * daylight saving, the hour a fall-back repeats would name two instants with
 * one value, so a live key or counter could read as already ended. In UTC every
 * value names one instant, and comparing two values compares the instants.
 *
 * `format()` is what the stores bind and compare with, so a statement the query
 * builder writes and a value the model reads agree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Database\Eloquent\CastsAttributes<\Carbon\CarbonImmutable, \DateTimeInterface|int>
 *
 * @internal
 */
final class UtcDateTime implements CastsAttributes
{
    /**
     * The instant, or the Unix time, as the model's connection stores times, in
     * UTC, to the whole second.
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
     * The stored value as the instant it names in UTC, or `null` when there is
     * none.
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
     * The instant, or the Unix time, as it is stored; `null` for none.
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
