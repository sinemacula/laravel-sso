<?php

declare(strict_types = 1);

/*
 * The callback route of `docs/guides/oidc-callback.md` (SSO-12.5), as an
 * application's routes file holds it: a `GET` route on the path
 * `sso.endpoints.paths.callback` builds each connection's callback from, so
 * the URL the package sends as `redirect_uri` is the one the application
 * serves, handing the request to the completion helper through the
 * application's controller.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

use Illuminate\Support\Facades\Route;
use Tests\Integration\Examples\OidcCallback\SsoCompletionController;

// @snippet-start oidc-callback-route
Route::get('/auth/sso/connections/{connection}/callback', [SsoCompletionController::class, 'callback']);
// @snippet-end oidc-callback-route
