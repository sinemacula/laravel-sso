<?php

declare(strict_types = 1);

/*
 * The SAML metadata guide's `bootstrap/app.php` (SSO-2.8, SSO-11.12,
 * SSO-12.5), from the builder on: an application's file starts from
 * `Application::configure()`, and `SamlMetadataScheduleExampleTest` hands in
 * the builder of the application under test instead, since configuring a
 * second application would replace it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\ApplicationBuilder;

return static fn (ApplicationBuilder $builder): Application => $builder
    // @snippet-start saml-metadata-schedule
    // bootstrap/app.php
    ->withSchedule(function (Schedule $schedule): void {
        $schedule->command('sso:metadata:refresh')->everyFiveMinutes();
    })
    // @snippet-end saml-metadata-schedule
    ->create();
