<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The caps on what an attribute mapping carries (SSO-2.10), read from
 * `sso.mapping` on each call (SSO-11.2), each failing closed with an
 * `InvalidArgumentException` naming its key when it is malformed; `[mapping]`
 * reports the same at boot.
 *
 * - `max_value_length`: the longest mapped value kept, 64 to 65535 characters
 *   (default 1024).
 * - `max_values`: the most values one mapped attribute keeps (a list of groups,
 *   say), 1 to 10000 (default 100).
 * - `max_custom_attributes`: the most custom keys a connection's mapping may
 *   declare beside the standard ones, 0 to 100 (default 20).
 *
 * Mapped values are profile data: a value past a cap is refused when a mapping
 * is saved and cut when a result is built, never used to select an identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MappingLimits
{
    /** @var int The longest mapped value kept when none is configured, in characters. */
    public const int DEFAULT_MAX_VALUE_LENGTH = 1024;

    /** @var int The most values of one attribute kept when none is configured. */
    public const int DEFAULT_MAX_VALUES = 100;

    /** @var int The most custom keys a mapping may declare when none is configured. */
    public const int DEFAULT_MAX_CUSTOM_ATTRIBUTES = 20;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the caps are read from. */
        private Repository $config,
    ) {}

    /**
     * The longest mapped value kept, in characters.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxValueLength(): int
    {
        return IntegerSetting::read($this->config, 'sso.mapping.max_value_length', self::DEFAULT_MAX_VALUE_LENGTH, 64, 65535);
    }

    /**
     * The most values one mapped attribute keeps.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxValues(): int
    {
        return IntegerSetting::read($this->config, 'sso.mapping.max_values', self::DEFAULT_MAX_VALUES, 1, 10000);
    }

    /**
     * The most custom keys a connection's mapping may declare.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxCustomAttributes(): int
    {
        return IntegerSetting::read($this->config, 'sso.mapping.max_custom_attributes', self::DEFAULT_MAX_CUSTOM_ATTRIBUTES, 0, 100);
    }
}
