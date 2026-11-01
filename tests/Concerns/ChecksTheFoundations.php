<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Foundation\Application;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Binds the configuration checker to the foundations' own checks (the switches,
 * extensions, storage, endpoints and applications), so a test of how the checks
 * are run and reported does not depend on the checks of the parts of the
 * package each item adds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ChecksTheFoundations
{
    /** @var list<string> The subjects of the foundations' checks. */
    private static array $foundations = ['features', 'extensions', 'storage', 'endpoints', 'applications'];

    /**
     * Bind the checker to the foundations' checks.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected static function checkTheFoundations(Application $app): void
    {
        $checks = array_intersect_key(SsoServiceProvider::CONFIGURATION_CHECKS, array_flip(self::$foundations));

        $app->bind(ConfigurationChecker::class, static fn (Application $app): ConfigurationChecker => new ConfigurationChecker($app, $checks));
    }
}
