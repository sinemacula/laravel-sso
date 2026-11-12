<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Support;

use Illuminate\Container\Container;

/**
 * Forgets the package's per-request state, and nothing else.
 *
 * For long-running processes that cannot forget every scoped instance, as
 * Octane and the queue worker do.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RequestState
{
    /**
     * Forget the instances held under the package's scoped keys.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return void
     */
    public static function forget(Container $container): void
    {
        foreach (PackageDefaults::scoped() as $abstract) {
            $container->forgetInstance($abstract);
        }
    }
}
