<?php

declare(strict_types = 1);

/*
 * The `routes/console.php` schedule of `docs/guides/single-use-store.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

// @snippet-start single-use-model-prune
use Illuminate\Support\Facades\Schedule;
use SineMacula\Laravel\Sso\Models\SingleUseKey;

Schedule::command('model:prune', [
    '--model' => [SingleUseKey::class],
])->hourly();
// @snippet-end single-use-model-prune
