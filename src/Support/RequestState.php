<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Support;

use Illuminate\Container\Container;

/**
 * Forget the package's per-request state, and nothing else.
 *
 * Octane and Laravel's queue worker forget every scoped instance between units
 * of work, the package's with the rest. A long-running process that must keep
 * what Laravel or another package scopes calls `forget()` between its units of
 * work instead: it forgets the package's scoped defaults and its own scoped
 * state, so the next unit builds them afresh. The singleton defaults, the
 * stranded transactions and whatever the application bound over a contract are
 * kept.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RequestState
{
    /**
     * Forget the scoped instances the container holds under the package's
     * scoped keys.
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
