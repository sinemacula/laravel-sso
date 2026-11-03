<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Events;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\Sso\Events\FlowFailed;

/**
 * The service provider of `docs/guides/events.md` (SSO-10.4, SSO-12.5) of an
 * application with `laravel-audit-log` and without `laravel-iam`: in `boot()`
 * it maps the package's failed flows through its own mapper, against the
 * examples' stand-in for that sibling's facade (`Events/AuditLog`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuditLogServiceProvider extends ServiceProvider
{
    /**
     * Map the events the application records.
     *
     * @return void
     */
    public function boot(): void
    {
        // @snippet-start audit-log-map
        AuditLog::map(FlowFailed::class, SsoAuditMapper::class);
        // @snippet-end audit-log-map
    }
}
