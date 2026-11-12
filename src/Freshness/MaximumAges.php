<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Freshness;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * Each operation's maximum authentication age, read on each call and failing
 * closed when malformed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MaximumAges
{
    /** @var string The key the maximum ages are configured under. */
    public const string BLOCK = 'sso.freshness.max_age_seconds';

    /** @var int The default maximum age, in seconds. */
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
