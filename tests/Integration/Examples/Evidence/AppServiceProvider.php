<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Evidence;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy;

/**
 * The example application's service provider (SSO-8.7): it opts into provider
 * evidence by binding the package's policy, which judges each result by the
 * policy its connection holds, in place of the default that accepts nothing. It
 * registers after the package's provider, as an application's providers do, so
 * its binding replaces the default as any later binding does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Bind the package's per-connection evidence policy.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start evidence-policy
        $this->app->scoped(EvidencePolicy::class, ConnectionEvidencePolicy::class);
        // @snippet-end evidence-policy
    }
}
