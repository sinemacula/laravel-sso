<?php

declare(strict_types = 1);

/*
 * The installation guide's `bootstrap/app.php` (SSO-11.11, SSO-12.5), from the
 * builder on: an application's file starts from `Application::configure()`,
 * and `InstallationExampleTest` hands in the builder of the application under
 * test instead, since configuring a second application would replace it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\ApplicationBuilder;
use SineMacula\Laravel\Sso\Operations\OperationsSchedule;

return static fn (ApplicationBuilder $builder): Application => $builder
    // @snippet-start installation-schedule
    // bootstrap/app.php
    ->withSchedule(function (Schedule $schedule): void {
        app(OperationsSchedule::class)->register($schedule);
    })
    // @snippet-end installation-schedule
    ->create();
