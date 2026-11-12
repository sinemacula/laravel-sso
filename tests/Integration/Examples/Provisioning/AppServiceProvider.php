<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Provisioning;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;

/**
 * Registers the provisioning listener synchronously, so it runs before any
 * handoff is issued.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Register the provisioning listener.
     *
     * @return void
     */
    public function boot(): void
    {
        // @snippet-start provisioning-registration
        Event::listen(ResultUnlinked::class, ProvisionNewPerson::class);
        // @snippet-end provisioning-registration
    }
}
