<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * How the scheduled refresh of a connection's metadata runs, and how long what
 * it applied is used (SSO-2.8, SSO-11.12), read from `sso.metadata` on each
 * call, so nothing is kept across requests (SSO-11.2), each failing closed with
 * an `InvalidArgumentException` naming its key when it is malformed;
 * `[metadata]` reports the same at boot.
 *
 * - `refresh_interval_seconds`: how long after a successful refresh the next is
 *   due, an hour to a week (default a day).
 * - `backoff_initial_seconds` and `backoff_max_seconds`: after a failed refresh
 *   the next is due after the initial wait, doubling with each failure in a row
 *   up to the maximum, a minute to an hour (default 5 minutes) and 5 minutes to
 *   a day (default 6 hours); a success resets it.
 * - `stale_limit_seconds`: how long after the last validated fetch what a
 *   refresh applied is still used, a day to a year (default 30 days), or `0`
 *   for no limit, which an application must set explicitly; checked again when
 *   a refresh commits.
 * - `claim_seconds`: how long a server's claim on a connection's refresh holds
 *   while it fetches, so racing servers refresh it once, 30 seconds to an hour
 *   (default 5 minutes); an administrator's refresh skips the backoff, never
 *   the claim.
 *
 * The scheduled command must run more often than the initial backoff, so a
 * failed refresh is retried when it falls due.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MetadataSettings
{
    /** @var int How long after a success the next refresh is due when none is configured, in seconds (a day). */
    public const int DEFAULT_REFRESH_INTERVAL_SECONDS = 86400;

    /** @var int The first wait after a failure when none is configured, in seconds (5 minutes). */
    public const int DEFAULT_BACKOFF_INITIAL_SECONDS = 300;

    /** @var int The longest wait after failures when none is configured, in seconds (6 hours). */
    public const int DEFAULT_BACKOFF_MAX_SECONDS = 21600;

    /** @var int How long what a refresh applied is used when none is configured, in seconds (30 days). */
    public const int DEFAULT_STALE_LIMIT_SECONDS = 2592000;

    /** @var int How long a refresh claim holds when none is configured, in seconds (5 minutes). */
    public const int DEFAULT_CLAIM_SECONDS = 300;

    /** @var int The shortest stale limit other than none, in seconds (a day). */
    public const int MIN_STALE_LIMIT_SECONDS = 86400;

    /** @var int The longest stale limit, in seconds (a year). */
    public const int MAX_STALE_LIMIT_SECONDS = 31536000;

    /** @var string The key of the stale limit. */
    private const string STALE_LIMIT_KEY = 'sso.metadata.stale_limit_seconds';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the settings are read from. */
        private Repository $config,
    ) {}

    /**
     * How long after a successful refresh the next is due, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function refreshIntervalSeconds(): int
    {
        return IntegerSetting::read($this->config, 'sso.metadata.refresh_interval_seconds', self::DEFAULT_REFRESH_INTERVAL_SECONDS, 3600, 604800);
    }

    /**
     * The wait after the first failure in a row, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function backoffInitialSeconds(): int
    {
        return IntegerSetting::read($this->config, 'sso.metadata.backoff_initial_seconds', self::DEFAULT_BACKOFF_INITIAL_SECONDS, 60, 3600);
    }

    /**
     * The longest wait after failures in a row, in seconds, never shorter than
     * the first.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function backoffMaxSeconds(): int
    {
        return IntegerSetting::read($this->config, 'sso.metadata.backoff_max_seconds', self::DEFAULT_BACKOFF_MAX_SECONDS, $this->backoffInitialSeconds(), 86400);
    }

    /**
     * The wait before the next attempt after the number of failures in a row,
     * one or more: the first wait doubled for each failure after the first, up
     * to the longest.
     *
     * @param  int  $failures
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function backoffSeconds(int $failures): int
    {
        $wait = $this->backoffInitialSeconds();
        $max  = $this->backoffMaxSeconds();

        for ($failure = 1; $failure < $failures && $wait < $max; $failure++) {
            $wait *= 2;
        }

        return min($wait, $max);
    }

    /**
     * How long after the last validated fetch what a refresh applied is used,
     * in seconds, or `null` for no limit.
     *
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    public function staleLimitSeconds(): ?int
    {
        $value = $this->config->get(self::STALE_LIMIT_KEY, self::DEFAULT_STALE_LIMIT_SECONDS);

        if (IntegerSetting::parse($value) === 0) {
            return null;
        }

        return IntegerSetting::from(self::STALE_LIMIT_KEY, $value, self::MIN_STALE_LIMIT_SECONDS, self::MAX_STALE_LIMIT_SECONDS);
    }

    /**
     * How long a server's claim on a refresh holds, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function claimSeconds(): int
    {
        return IntegerSetting::read($this->config, 'sso.metadata.claim_seconds', self::DEFAULT_CLAIM_SECONDS, 30, 3600);
    }
}
