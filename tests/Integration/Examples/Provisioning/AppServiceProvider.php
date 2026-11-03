<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Provisioning;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;

/**
 * The example application's service provider (SSO-8.6): it registers the
 * provisioning listener on the unlinked-result event's class, synchronously, so
 * the event reaches it during the completion, before any handoff is issued.
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
