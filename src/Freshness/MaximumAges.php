<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Freshness;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * The maximum age of the caller's authentication each operation SSO-2.12 lists
 * requires, in seconds, read from `sso.freshness.max_age_seconds.<operation>`
 * on each call (SSO-11.2).
 *
 * Each defaults to 300 seconds and may be set from 1 to 3600; a value that is
 * not an integer in that range, or the digit string `env()` gives for one,
 * fails closed with an `InvalidArgumentException` naming the key, rather than
 * loosening the requirement it was meant to set. `[freshness]` reports the same
 * at boot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MaximumAges
{
    /** @var string The key, under `sso.`, the maximum ages are configured under. */
    public const string BLOCK = 'sso.freshness.max_age_seconds';

    /** @var int The maximum age an operation requires when none is configured, in seconds. */
    public const int DEFAULT_SECONDS = 300;

    /** @var int The least maximum age that may be configured, in seconds. */
    public const int MIN_SECONDS = 1;

    /** @var int The greatest maximum age that may be configured, in seconds (an hour). */
    public const int MAX_SECONDS = 3600;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the maximum ages are read from. */
        private Repository $config,
    ) {}

    /**
     * The maximum age the operation requires, in seconds.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function for(FreshnessOperation $operation): int
    {
        return IntegerSetting::read($this->config, self::BLOCK . '.' . $operation->configKey(), self::DEFAULT_SECONDS, self::MIN_SECONDS, self::MAX_SECONDS);
    }
}
