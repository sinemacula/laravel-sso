<?php

declare(strict_types = 1);

/*
 * The example application's routes (SSO-12.5), as its `routes/api.php`: the
 * layout `docs/guides/example-application.md` describes, each route calling one
 * of the package's helpers through its controller. Laravel prefixes the file's
 * routes with `api`, which `sso.endpoints.base_url` carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

use Illuminate\Support\Facades\Route;
use Tests\Integration\Examples\Routes\Controllers\SsoCompletionController;
use Tests\Integration\Examples\Routes\Controllers\SsoConnectionController;
use Tests\Integration\Examples\Routes\Controllers\SsoDomainController;
use Tests\Integration\Examples\Routes\Controllers\SsoLinkController;
use Tests\Integration\Examples\Routes\Controllers\SsoMetadataController;
use Tests\Integration\Examples\Routes\Controllers\SsoReauthenticationController;
use Tests\Integration\Examples\Routes\Controllers\SsoSessionController;
use Tests\Integration\Examples\Routes\Controllers\SsoStartController;

// @snippet-start route-layout
Route::post('/auth/sso/authorization-requests', [SsoStartController::class, 'signIn']);
Route::post('/auth/sso/connections/{connection}/assertions', [SsoCompletionController::class, 'assertion']);
Route::get('/auth/sso/connections/{connection}/callback', [SsoCompletionController::class, 'callback']);
Route::get('/auth/sso/connections/{connection}/metadata', [SsoMetadataController::class, 'metadata']);
Route::get('/auth/sso/connections/{connection}/jwks', [SsoMetadataController::class, 'jwks']);
Route::post('/auth/sessions', [SsoSessionController::class, 'store']);

Route::middleware('auth')->group(static function (): void {
    Route::post('/auth/sso/links/authorization-requests', [SsoStartController::class, 'link']);
    Route::post('/auth/sso/links', [SsoLinkController::class, 'store']);
    Route::get('/auth/sso/links', [SsoLinkController::class, 'index']);
    Route::delete('/auth/sso/links/{link}', [SsoLinkController::class, 'destroy']);
    Route::post('/auth/sso/reauthentications/authorization-requests', [SsoStartController::class, 'reauthenticate']);
    Route::post('/auth/sso/reauthentications', [SsoReauthenticationController::class, 'store']);
});

Route::middleware(['auth', 'can:manage-sso'])->group(static function (): void {
    Route::get('/auth/sso/connections', [SsoConnectionController::class, 'index']);
    Route::post('/auth/sso/connections', [SsoConnectionController::class, 'store']);
    Route::get('/auth/sso/connections/{connection}', [SsoConnectionController::class, 'show']);
    Route::patch('/auth/sso/connections/{connection}', [SsoConnectionController::class, 'update']);
    Route::delete('/auth/sso/connections/{connection}', [SsoConnectionController::class, 'destroy']);
    Route::post('/auth/sso/connections/{connection}/enable', [SsoConnectionController::class, 'enable']);
    Route::post('/auth/sso/connections/{connection}/disable', [SsoConnectionController::class, 'disable']);
    Route::post('/auth/sso/connections/{connection}/domains', [SsoDomainController::class, 'store']);
    Route::delete('/auth/sso/connections/{connection}/domains/{domain}', [SsoDomainController::class, 'destroy']);
    Route::post('/auth/sso/connections/{connection}/domains/{domain}/verifications', [SsoDomainController::class, 'verify']);
});
// @snippet-end route-layout
