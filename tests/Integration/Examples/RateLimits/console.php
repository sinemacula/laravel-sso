<?php

declare(strict_types = 1);

/*
 * The `routes/console.php` schedule of `docs/guides/rate-limits.md`.
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
