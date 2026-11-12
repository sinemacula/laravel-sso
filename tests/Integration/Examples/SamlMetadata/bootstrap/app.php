<?php

declare(strict_types = 1);

/*
 * The SAML metadata guide's `bootstrap/app.php`, from the builder on; the test
 * hands in its own builder, since configuring a second application replaces it.
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
