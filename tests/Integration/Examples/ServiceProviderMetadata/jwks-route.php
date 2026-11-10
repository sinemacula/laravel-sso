<?php

declare(strict_types = 1);

/*
 * The public keys route of `docs/guides/service-provider-metadata.md`
 * (SSO-5.9, SSO-12.5), as an application's routes file holds it: a `GET` route
 * on the path `sso.endpoints.paths.jwks` builds each OIDC connection's
 * `jwks_uri` from, with no authentication and no tenant, answering the
 * connection's current and next public keys, and `404` for a connection with
 * none to serve.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

// @snippet-start service-provider-jwks-route
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;

Route::get(config()->string('sso.endpoints.paths.jwks'), static function (string $connection, ServiceProviderDescriptions $descriptions): Response {
    $keys = $descriptions->publicKeys($connection);

    abort_unless($keys->isAvailable(), 404);

    return response($keys->body, 200, [
        'Content-Type'  => $keys->contentType,
        'Cache-Control' => 'public, max-age=300',
    ]);
})->name('sso.jwks');
// @snippet-end service-provider-jwks-route
