<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Evidence;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy;

/**
 * The example application's service provider, opting into provider evidence.
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
