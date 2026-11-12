<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Sso\Config\Enums\Feature;

/**
 * Which features are switched on in `sso.features`, read on each call.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class Features
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The answer a flow acts on; a malformed switch fails closed.
     *
     * @param  \SineMacula\Laravel\Sso\Config\Enums\Feature  $feature
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public static function enabled(Feature $feature): bool
    {
        return BooleanSetting::isOn($feature->key(), Config::get($feature->key(), $feature->isOnByDefault()));
    }

    /**
     * The answer the configuration checks act on: a malformed switch counts as
     * on, so what it would enable is checked too.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Sso\Config\Enums\Feature  $feature
     * @return bool
     */
    public static function requested(Repository $config, Feature $feature): bool
    {
        return BooleanSetting::parse($config->get($feature->key(), $feature->isOnByDefault())) !== false;
    }

    /**
     * Whether any protocol is requested; checks of what a flow needs apply only
     * then.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function isInUse(Repository $config): bool
    {
        return self::requested($config, Feature::SAML2) || self::requested($config, Feature::OIDC);
    }
}
