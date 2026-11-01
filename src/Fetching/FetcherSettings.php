<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The outbound fetcher's settings (SSO-2.9), under `sso.fetcher`: its time
 * caps, its response size cap, how many redirects a request without a
 * credential may follow, and the CIDR ranges the application refuses on top of
 * the ones always refused.
 *
 * Each value is read on each call, so nothing is kept across requests
 * (SSO-11.2). A value that is malformed or outside its range fails closed with
 * an `InvalidArgumentException` naming its key and what it must be, never the
 * value, rather than falling back to a default or clamping to the range.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FetcherSettings
{
    /** @var int The time a request may take when none is configured, in seconds. */
    public const int DEFAULT_TIMEOUT_SECONDS = 10;

    /** @var int The time a connection may take when none is configured, in seconds. */
    public const int DEFAULT_CONNECT_TIMEOUT_SECONDS = 5;

    /** @var int The largest response accepted when no cap is configured, in bytes (1 MiB). */
    public const int DEFAULT_MAX_RESPONSE_BYTES = 1048576;

    /** @var int The redirects followed when none is configured. */
    public const int DEFAULT_MAX_REDIRECTS = 3;

    /** @var string The problem of a connect timeout longer than the timeout. */
    public const string CONNECT_TIMEOUT_EXCEEDS_TIMEOUT = 'sso.fetcher.connect_timeout_seconds must not exceed sso.fetcher.timeout_seconds.';

    /** @var string The key the request timeout is configured under. */
    private const string TIMEOUT_KEY = 'sso.fetcher.timeout_seconds';

    /** @var string The key the connect timeout is configured under. */
    private const string CONNECT_TIMEOUT_KEY = 'sso.fetcher.connect_timeout_seconds';

    /** @var string The key the response size cap is configured under. */
    private const string MAX_RESPONSE_BYTES_KEY = 'sso.fetcher.max_response_bytes';

    /** @var string The key the redirect cap is configured under. */
    private const string MAX_REDIRECTS_KEY = 'sso.fetcher.max_redirects';

    /** @var string The key the added refused ranges are configured under. */
    private const string REFUSED_RANGES_KEY = 'sso.fetcher.refused_ranges';

    /** @var string The message of a refused range that is not a CIDR range, given the key and the index. */
    private const string NOT_A_RANGE = '%s.%d must be a CIDR range: an IPv4 address with /0 to /32, or an IPv6 address with /0 to /128.';

    /** @var string A CIDR range: an address, a slash and a prefix length with no leading zero. */
    private const string CIDR = '#^([0-9A-Fa-f:.]+)/(0|[1-9][0-9]{0,2})$#D';

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
     * The time a request may take, from connecting to the last byte of its
     * response, in seconds: 1 to 60, 10 by default.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function timeoutSeconds(): int
    {
        return IntegerSetting::read($this->config, self::TIMEOUT_KEY, self::DEFAULT_TIMEOUT_SECONDS, 1, 60);
    }

    /**
     * The time connecting may take, in seconds: 1 to 30, 5 by default.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function connectTimeoutSeconds(): int
    {
        return IntegerSetting::read($this->config, self::CONNECT_TIMEOUT_KEY, self::DEFAULT_CONNECT_TIMEOUT_SECONDS, 1, 30);
    }

    /**
     * The largest response body accepted, in bytes: 1024 to 10485760 (10 MiB),
     * 1048576 (1 MiB) by default.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxResponseBytes(): int
    {
        return IntegerSetting::read($this->config, self::MAX_RESPONSE_BYTES_KEY, self::DEFAULT_MAX_RESPONSE_BYTES, 1024, 10485760);
    }

    /**
     * The redirects a request without a credential may follow: 0 to 10, 3 by
     * default.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxRedirects(): int
    {
        return IntegerSetting::read($this->config, self::MAX_REDIRECTS_KEY, self::DEFAULT_MAX_REDIRECTS, 0, 10);
    }

    /**
     * The CIDR ranges the application refuses on top of the ones always
     * refused, `[]` by default: a list of IPv4 ranges (`/0` to `/32`) or IPv6
     * ranges (`/0` to `/128`). A list that is not a list of strings, or an
     * entry that is not such a range, fails closed, naming the key or the
     * entry's key.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function refusedRanges(): array
    {
        $ranges = $this->config->get(self::REFUSED_RANGES_KEY, []);

        if (!is_array($ranges) || !array_is_list($ranges)) {
            throw new \InvalidArgumentException(sprintf('%s must be a list of CIDR ranges.', self::REFUSED_RANGES_KEY));
        }

        foreach ($ranges as $index => $range) {
            if (!is_string($range) || !self::isRange($range)) {
                throw new \InvalidArgumentException(sprintf(self::NOT_A_RANGE, self::REFUSED_RANGES_KEY, $index));
            }
        }

        /** @var list<string> $ranges */
        return $ranges;
    }

    /**
     * Read every setting, failing on the first that is malformed, then require
     * the connect timeout to be no longer than the timeout.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->maxResponseBytes();
        $this->maxRedirects();
        $this->refusedRanges();
        $this->assertConnectTimeoutWithinTimeout();
    }

    /**
     * Require the connect timeout to be no longer than the timeout, reading
     * both.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function assertConnectTimeoutWithinTimeout(): void
    {
        $timeout = $this->timeoutSeconds();

        if ($this->connectTimeoutSeconds() > $timeout) {
            throw new \InvalidArgumentException(self::CONNECT_TIMEOUT_EXCEEDS_TIMEOUT);
        }
    }

    /**
     * Whether the string is a CIDR range: a canonical IPv4 address with a
     * prefix of 0 to 32, or an IPv6 address with a prefix of 0 to 128.
     *
     * @param  string  $range
     * @return bool
     */
    public static function isRange(string $range): bool
    {
        if (preg_match(self::CIDR, $range, $matches) !== 1) {
            return false;
        }

        $prefix = (int) $matches[2];

        if (filter_var($matches[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return $prefix <= 32;
        }

        return filter_var($matches[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false && $prefix <= 128;
    }
}
