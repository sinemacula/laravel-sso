<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The flows' own settings, read on each call and failing closed when malformed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FlowSettings
{
    /** @var int The default authorisation request lifetime, in seconds. */
    public const int DEFAULT_REQUEST_TTL_SECONDS = 600;

    /** @var int The shortest an authorisation request may live, in seconds. */
    public const int MIN_REQUEST_TTL_SECONDS = 60;

    /** @var int The longest an authorisation request may live, in seconds. */
    public const int MAX_REQUEST_TTL_SECONDS = 900;

    /** @var int The default least time of a discovery start, in milliseconds. */
    public const int DEFAULT_DISCOVERY_DURATION_MILLISECONDS = 250;

    /** @var int The smallest least time a discovery start may take, in milliseconds. */
    public const int MIN_DISCOVERY_DURATION_MILLISECONDS = 50;

    /** @var int The largest least time a discovery start may take, in milliseconds. */
    public const int MAX_DISCOVERY_DURATION_MILLISECONDS = 2000;

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
     * How long an authorisation request waits for its response, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function requestTtlSeconds(): int
    {
        return IntegerSetting::read(
            $this->config,
            'sso.authorization_requests.ttl_seconds',
            self::DEFAULT_REQUEST_TTL_SECONDS,
            self::MIN_REQUEST_TTL_SECONDS,
            self::MAX_REQUEST_TTL_SECONDS,
        );
    }

    /**
     * The least time a discovery start takes, in milliseconds; a timing
     * mitigation, not a guarantee.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function discoveryMinimumDurationMilliseconds(): int
    {
        return IntegerSetting::read(
            $this->config,
            'sso.discovery.minimum_duration_milliseconds',
            self::DEFAULT_DISCOVERY_DURATION_MILLISECONDS,
            self::MIN_DISCOVERY_DURATION_MILLISECONDS,
            self::MAX_DISCOVERY_DURATION_MILLISECONDS,
        );
    }
}
