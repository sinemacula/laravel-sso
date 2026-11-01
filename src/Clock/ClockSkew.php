<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Clock;

use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The clock skew every protocol time check allows, in seconds: SAML's
 * `NotBefore` and `NotOnOrAfter`, and OIDC's `exp`, `iat` and `auth_time`
 * (SSO-6.5, SSO-11.13).
 *
 * Read from `sso.clock.skew_seconds` on each call, so nothing is kept across
 * requests (SSO-11.2). It defaults to 60 seconds and is at most 300 (five
 * minutes); a value that is not an integer from 0 to 300, or the digit string
 * `env()` gives for one, fails closed with an `InvalidArgumentException` naming
 * the key, rather than widening or narrowing the window it was meant to set.
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

    /** @var int The greatest skew that may be configured, in seconds (five minutes). */
    public const int MAX_SECONDS = 300;

    /** @var string The key the skew is configured under. */
    private const string KEY = 'sso.clock.skew_seconds';

    /** @var int The least skew that may be configured, in seconds: none. */
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
