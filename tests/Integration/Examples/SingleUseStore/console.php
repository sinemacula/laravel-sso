<?php

declare(strict_types = 1);

/*
 * The schedule of `docs/guides/single-use-store.md` (SSO-11.5, SSO-12.5), as an
 * application's `routes/console.php` holds it: Laravel's `model:prune`, hourly,
 * naming the package's single-use keys, whose class is the one part of the
 * model that is public.
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
