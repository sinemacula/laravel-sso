<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * How large an identity provider's metadata may be, how the scheduled refresh
 * of a connection's metadata runs, and how long what it applied is used
 * (SSO-2.8, SSO-11.12), read from `sso.metadata` on each call, so nothing is
 * kept across requests (SSO-11.2), each failing closed with an
 * `InvalidArgumentException` naming its key when it is malformed; `[metadata]`
 * reports the same at boot.
 *
 * - `max_bytes`: the most bytes a metadata document may hold, given as XML or
 *   fetched, for an import and a refresh alike, in place of the fetcher's
 *   `max_response_bytes`: 64 KiB to 256 MiB (default 1 MiB). The whole document
 *   is held in memory, parsed and its signature checked in one piece, so a
 *   large federation aggregate needs memory of several times its size and
 *   seconds of processing (`metadata-refresh.md`).
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
 * - `queue`: where the scheduled command sends each connection's refresh, as a
 *   `RefreshConnectionMetadata` job: `connection` and `name` (`null` for the
 *   application's default queue connection and that connection's default
 *   queue; a connection must be one `queue.connections` configures),
 *   `timeout_seconds` (30 seconds to an hour, default a minute, never longer
 *   than `claim_seconds`, so a job never outlives its claim, and shorter than
 *   the queue connection's `retry_after` where it sets one, so a refresh still
 *   running is never reserved by a second worker) and `tries` (1 to 10,
 *   default 1: a failed refresh is retried by the backoff, not the queue).
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

    /** @var int The most bytes a metadata document may hold when none is configured (1 MiB). */
    public const int DEFAULT_MAX_BYTES = 1048576;

    /** @var int The smallest cap a metadata document may be held to (64 KiB). */
    public const int MIN_MAX_BYTES = 65536;

    /** @var int The hard ceiling of the cap a metadata document may be held to (256 MiB). */
    public const int MAX_MAX_BYTES = 268435456;

    /** @var int How long a queued refresh may run when none is configured, in seconds (a minute, under the stock `retry_after` of 90). */
    public const int DEFAULT_TIMEOUT_SECONDS = 60;

    /** @var int How many times a queued refresh is attempted when none is configured. */
    public const int DEFAULT_TRIES = 1;

    /** @var string The key of the stale limit. */
    private const string STALE_LIMIT_KEY = 'sso.metadata.stale_limit_seconds';

    /** @var string The key of the queue connection a refresh is sent to. */
    private const string QUEUE_CONNECTION_KEY = 'sso.metadata.queue.connection';

    /** @var string The key of the queue a refresh is sent to. */
    private const string QUEUE_NAME_KEY = 'sso.metadata.queue.name';

    /** @var string The key of a queued refresh's timeout. */
    private const string TIMEOUT_KEY = 'sso.metadata.queue.timeout_seconds';

    /** @var string The problem of a timeout not under the queue connection's `retry_after`, by key and connection. */
    private const string PAST_RETRY_AFTER = '%s must be shorter than the retry_after of queue connection [%s], so a refresh still running is never reserved again.';

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

    /**
     * The most bytes a metadata document may hold, fetched or given.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxBytes(): int
    {
        return IntegerSetting::read($this->config, 'sso.metadata.max_bytes', self::DEFAULT_MAX_BYTES, self::MIN_MAX_BYTES, self::MAX_MAX_BYTES);
    }

    /**
     * The queue connection a refresh is sent to, or `null` for the
     * application's default.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function queueConnection(): ?string
    {
        $connection = $this->optionalName(self::QUEUE_CONNECTION_KEY);

        if ($connection !== null && !is_array($this->config->get('queue.connections.' . $connection))) {
            throw new \InvalidArgumentException(sprintf('%s names [%s], which queue.connections does not configure.', self::QUEUE_CONNECTION_KEY, $connection));
        }

        return $connection;
    }

    /**
     * The queue a refresh is sent to, or `null` for the connection's default.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function queueName(): ?string
    {
        return $this->optionalName(self::QUEUE_NAME_KEY);
    }

    /**
     * How long a queued refresh may run, in seconds, never longer than a claim
     * holds and shorter than the queue connection's `retry_after` where it sets
     * one. A claim or a connection that is malformed is left to its own check
     * to report, once.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function timeoutSeconds(): int
    {
        $timeout = IntegerSetting::read($this->config, self::TIMEOUT_KEY, self::DEFAULT_TIMEOUT_SECONDS, 30, 3600);
        $claim   = IntegerSetting::parse($this->config->get('sso.metadata.claim_seconds', self::DEFAULT_CLAIM_SECONDS));

        if ($claim !== null && $timeout > $claim) {
            throw new \InvalidArgumentException(sprintf('%s must not exceed sso.metadata.claim_seconds, so a refresh never outlives its claim.', self::TIMEOUT_KEY));
        }

        [$connection, $retryAfter] = $this->retryAfter();

        if ($retryAfter !== null && $timeout >= $retryAfter) {
            throw new \InvalidArgumentException(sprintf(self::PAST_RETRY_AFTER, self::TIMEOUT_KEY, $connection));
        }

        return $timeout;
    }

    /**
     * How many times a queued refresh is attempted.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function tries(): int
    {
        return IntegerSetting::read($this->config, 'sso.metadata.queue.tries', self::DEFAULT_TRIES, 1, 10);
    }

    /**
     * The queue connection a refresh is sent to, by name, and the `retry_after`
     * it sets, `null` when it sets none (as `sync` and `sqs` do) or names no
     * connection that can be read.
     *
     * @return array{0: string, 1: ?int}
     */
    private function retryAfter(): array
    {
        $connection = $this->config->get(self::QUEUE_CONNECTION_KEY);
        $connection = is_string($connection) && $connection !== '' ? $connection : $this->config->get('queue.default');

        if (!is_string($connection) || $connection === '') {
            return ['', null];
        }

        return [$connection, IntegerSetting::parse($this->config->get('queue.connections.' . $connection . '.retry_after'))];
    }

    /**
     * The name configured under the key: `null` for none or an empty string, a
     * string of at most 255 bytes otherwise.
     *
     * @param  string  $key
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function optionalName(string $key): ?string
    {
        $value = $this->config->get($key);

        if ($value === null || $value === '') {
            return null;
        }

        if (!is_string($value) || strlen($value) > 255) {
            throw new \InvalidArgumentException(sprintf('%s must be a name of at most 255 bytes, or null.', $key));
        }

        return $value;
    }
}
