<?php

declare(strict_types = 1);

/*
 * The completion routes of `docs/guides/completion-responses.md` (SSO-12.5),
 * as an application's `routes/api.php` holds them: the SAML assertion consumer
 * service and the OIDC callback, each answering through the controller that
 * turns a completion's result into its response. Laravel prefixes the file's
 * routes with `api`, which `sso.endpoints.base_url` carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

use Illuminate\Support\Facades\Route;
use Tests\Integration\Examples\CompletionResponses\SsoCompletionController;

// @snippet-start response-routes
// routes/api.php
Route::post('/auth/sso/connections/{connection}/assertions', [SsoCompletionController::class, 'assertion']);
Route::get('/auth/sso/connections/{connection}/callback', [SsoCompletionController::class, 'callback']);
// @snippet-end response-routes
