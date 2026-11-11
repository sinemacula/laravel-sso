<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Sso\Config\Enums\Feature;

/**
 * Which features the application has switched on in `sso.features`, read on
 * each call so nothing is kept across requests (SSO-11.2).
 *
 * `enabled()` is the answer a flow acts on: a switch that is neither on nor off
 * fails closed with an `InvalidArgumentException` naming its key. `requested()`
 * is the answer the configuration checks act on: a malformed switch counts as
 * on there, so the settings it would enable are checked as well as the switch
 * itself, and a check never fails to say why. `requested()` and `isInUse()`
 * read the repository they are given, so a composing package's check can pass
 * its own.
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
     * Whether the feature is switched on.
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
     * Whether the feature is switched on, or its switch is malformed and so may
     * have been meant to be.
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
     * Whether the package is in use: a protocol is switched on, or its switch
     * is malformed. Every check of what a flow needs applies only then.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function isInUse(Repository $config): bool
    {
        return self::requested($config, Feature::SAML2) || self::requested($config, Feature::OIDC);
    }
}
