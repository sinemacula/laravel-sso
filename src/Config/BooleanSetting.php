<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config;

use Illuminate\Contracts\Config\Repository;

/**
 * Reads a switch the one way every settings class reads one: a boolean, or the
 * forms `env()` and a deploy pipeline give for one (`1` and `0` as integers or
 * strings, `true` and `false` as strings). Anything else fails closed with an
 * `InvalidArgumentException` naming the key, rather than guessing whether a
 * feature was meant to be on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BooleanSetting
{
    /** @var array<int|string, bool> The strings a switch may be given as, and what each means (PHP keys `1` and `0` as integers, and finds them by either). */
    private const array STRINGS = [
        '1'     => true,
        '0'     => false,
        'true'  => true,
        'false' => false,
    ];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The switch under the key, or the default when it is not set.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $key
     * @param  bool  $default
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public static function read(Repository $config, string $key, bool $default): bool
    {
        return self::isOn($key, $config->get($key, $default));
    }

    /**
     * The value already read for the key, as a boolean.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public static function isOn(string $key, mixed $value): bool
    {
        $boolean = self::parse($value);

        if ($boolean === null) {
            throw new \InvalidArgumentException(sprintf('%s must be true or false.', $key));
        }

        return $boolean;
    }

    /**
     * The boolean the value names, or `null` when it names none.
     *
     * @param  mixed  $value
     * @return ?bool
     */
    public static function parse(mixed $value): ?bool
    {
        return match (true) {
            is_bool($value)            => $value,
            $value === 1, $value === 0 => $value === 1,
            is_string($value)          => self::STRINGS[$value] ?? null,
            default                    => null,
        };
    }
}
