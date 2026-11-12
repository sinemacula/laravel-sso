<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Clock;

use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The clock skew every protocol time check allows, read on each call and
 * failing closed when malformed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ClockSkew
{
    /** @var int The skew allowed when none is configured, in seconds. */
    public const int DEFAULT_SECONDS = 60;

    /** @var int The greatest skew that may be configured, in seconds. */
    public const int MAX_SECONDS = 300;

    /** @var string The key the skew is configured under. */
    private const string KEY = 'sso.clock.skew_seconds';

    /** @var int The least skew that may be configured, in seconds. */
    private const int MIN_SECONDS = 0;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The configured clock skew, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public static function seconds(): int
    {
        return IntegerSetting::from(self::KEY, Config::get(self::KEY, self::DEFAULT_SECONDS), self::MIN_SECONDS, self::MAX_SECONDS);
    }
}
