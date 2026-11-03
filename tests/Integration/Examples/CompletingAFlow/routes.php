<?php

declare(strict_types = 1);

/*
 * The completion routes of `docs/guides/completing-a-flow.md` (SSO-12.5), as an
 * application's `routes/api.php` holds them: the SAML assertion consumer
 * service and the OIDC callback, on the paths `sso.endpoints.paths` builds each
 * connection's URLs from, each calling the completion helper through the
 * example application's controller. They take no session, no CSRF token and no
 * authentication, since the completion checks the response itself.
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
