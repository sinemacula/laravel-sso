<?php

declare(strict_types = 1);

/*
 * The operations guide's `bootstrap/app.php` from the builder on. The test
 * hands in its own builder, since configuring a second application replaces it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\ApplicationBuilder;
use SineMacula\Laravel\Sso\Operations\OperationsSchedule;

return static fn (ApplicationBuilder $builder): Application => $builder
    // @snippet-start operations-schedule
    // bootstrap/app.php
    ->withSchedule(function (Schedule $schedule): void {
        app(OperationsSchedule::class)->register($schedule);
    })
    // @snippet-end operations-schedule
    ->create();
