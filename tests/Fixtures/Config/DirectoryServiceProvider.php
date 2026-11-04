<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Config;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;

/**
 * A composing package's service provider, adding its check to the package's
 * checker under `directory`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DirectoryServiceProvider extends ServiceProvider
{
    /**
     * Add the directory's check.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->callAfterResolving(ConfigurationChecks::class, static function (ConfigurationChecks $checks): void {
            $checks->add('directory', DirectoryCheck::class);
        });
    }
}
