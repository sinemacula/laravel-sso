<?php

declare(strict_types = 1);

/*
 * The application's OIDC callback route, on `sso.endpoints.paths.callback`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

use Illuminate\Support\Facades\Route;
use Tests\Integration\Examples\OidcCallback\SsoCompletionController;

// @snippet-start oidc-callback-route
Route::get('/auth/sso/connections/{connection}/callback', [SsoCompletionController::class, 'callback']);
// @snippet-end oidc-callback-route
