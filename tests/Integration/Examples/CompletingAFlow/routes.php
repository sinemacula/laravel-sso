<?php

declare(strict_types = 1);

/*
 * The completion routes of `docs/guides/completing-a-flow.md`, in
 * `routes/api.php`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

use Illuminate\Support\Facades\Route;
use Tests\Integration\Examples\Routes\Controllers\SsoCompletionController;

// @snippet-start completion-routes
Route::post('/auth/sso/connections/{connection}/assertions', [SsoCompletionController::class, 'assertion']);
Route::get('/auth/sso/connections/{connection}/callback', [SsoCompletionController::class, 'callback']);
// @snippet-end completion-routes
