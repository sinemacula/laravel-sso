<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The settings of the flows themselves, read on each call (SSO-11.2), each
 * failing closed with an `InvalidArgumentException` naming its key when it is
 * malformed; `[flows]` reports the same at boot.
 *
 * - `authorization_requests.ttl_seconds`: how long an authorisation request
 *   waits for its response, 60 to 900 seconds (default 600): a few minutes,
 *   capped (SSO-5.1).
 * - `discovery.minimum_duration_milliseconds`: the least time a discovery start
 *   takes, 50 to 2000 milliseconds (default 250), a timing mitigation that
 *   hides a match's extra work within it, not a guarantee that a match and a
 *   miss are indistinguishable (SSO-3.5). It cannot be turned off.
 *
 * A handoff code's lifetime is each application's own setting
 * (`Applications\Application::$handoffTtlSeconds`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FlowSettings
{
    /** @var int An authorisation request's lifetime when none is configured, in seconds. */
    public const int DEFAULT_REQUEST_TTL_SECONDS = 600;

    /** @var int The shortest an authorisation request may live, in seconds. */
    public const int MIN_REQUEST_TTL_SECONDS = 60;

    /** @var int The longest an authorisation request may live, in seconds. */
    public const int MAX_REQUEST_TTL_SECONDS = 900;

    /** @var int The least time a discovery start takes when none is configured, in milliseconds. */
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
     * The least time a discovery start takes, in milliseconds.
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
