<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * What an attribute mapping may carry (SSO-2.10), read from `sso.mapping` on
 * each call (SSO-11.2), each failing closed with an `InvalidArgumentException`
 * naming its key when it is malformed; `[mapping]` reports the same at boot.
 *
 * - `max_value_length`: the longest mapped value kept, 64 to 65535 characters
 *   (default 1024).
 * - `max_values`: the most values one mapped attribute keeps (a list of groups,
 *   say), 1 to 10000 (default 100).
 * - `custom_attributes`: the custom keys the application declares, which a
 *   connection's mapping may name beside the standard ones: a list of at most
 *   `MAX_CUSTOM_ATTRIBUTES` distinct keys, each of a custom target's form and
 *   none a standard or reserved target (default none, so a mapping names the
 *   standard targets alone). The application declares them, never a tenant
 *   administrator, so a key the application's code does not read is never
 *   mapped.
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

    /** @var int The most custom keys the application may declare. */
    public const int MAX_CUSTOM_ATTRIBUTES = 100;

    /** @var string The key the custom keys are declared under. */
    private const string CUSTOM_ATTRIBUTES = 'sso.mapping.custom_attributes';

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
     * The custom keys the application declares, in the order given.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function customAttributes(): array
    {
        $declared = $this->config->get(self::CUSTOM_ATTRIBUTES, []);

        if (!is_array($declared) || !array_is_list($declared) || count($declared) > self::MAX_CUSTOM_ATTRIBUTES) {
            throw self::malformedCustomAttributes();
        }

        $keys = [];

        foreach ($declared as $key) {

            if (!is_string($key) || !AttributeMapping::isCustomTarget($key)) {
                throw self::malformedCustomAttributes();
            }

            $keys[] = $key;
        }

        if (count(array_unique($keys)) !== count($keys)) {
            throw self::malformedCustomAttributes();
        }

        return $keys;
    }

    /**
     * The failure of a malformed declaration of custom keys.
     *
     * @return \InvalidArgumentException
     */
    private static function malformedCustomAttributes(): \InvalidArgumentException
    {
        return new \InvalidArgumentException(sprintf(
            '%s must be a list of at most %d distinct custom keys, each a lower-case letter then up to 63 lower-case letters, digits or underscores, '
            . 'and none a standard or reserved key.',
            self::CUSTOM_ATTRIBUTES,
            self::MAX_CUSTOM_ATTRIBUTES,
        ));
    }
}
