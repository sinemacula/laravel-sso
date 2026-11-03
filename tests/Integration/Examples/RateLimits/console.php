<?php

declare(strict_types = 1);

/*
 * The schedule of `docs/guides/rate-limits.md` (SSO-11.8, SSO-12.5), as an
 * application's `routes/console.php` holds it: Laravel's `model:prune`, hourly,
 * naming the package's counters, whose class is the one part of the model that
 * is public.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

// @snippet-start rate-limits-model-prune
use Illuminate\Support\Facades\Schedule;
use SineMacula\Laravel\Sso\Models\RateLimit;

Schedule::command('model:prune', [
    '--model' => [RateLimit::class],
])->hourly();
// @snippet-end rate-limits-model-prune
