<?php

declare(strict_types = 1);

/*
 * The domain rechecks guide's `bootstrap/app.php` (SSO-3.3, SSO-12.5), from
 * the builder on: an application's file starts from `Application::configure()`,
 * and `DomainRechecksExampleTest` hands in the builder of the application under
 * test instead, since configuring a second application would replace it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\ApplicationBuilder;

return static fn (ApplicationBuilder $builder): Application => $builder
    // @snippet-start recheck-schedule
    // bootstrap/app.php
    ->withSchedule(function (Schedule $schedule): void {
        $schedule->command('sso:domains:recheck')->hourly();
    })
    // @snippet-end recheck-schedule
    ->create();
