<?php

declare(strict_types = 1);

/*
 * The metadata route of `docs/guides/service-provider-metadata.md` (SSO-5.9,
 * SSO-12.5), as an application's routes file holds it: a `GET` route on the
 * path `sso.endpoints.paths.metadata` builds each connection's metadata URL
 * and entity id from, so the URL the metadata names is the one that serves it,
 * answering the description of the tenant's connection, and `404` for every
 * refusal alike. The application resolves the tenant before the route runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

// @snippet-start service-provider-metadata-route
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;

Route::get(config('sso.endpoints.paths.metadata'), static function (
    Request $request,
    string $connection,
    ServiceProviderDescriptions $descriptions,
): Response {
    // However your application resolves the tenant it serves: the host, a route
    // parameter, or a lookup of the connection id in your own records.
    $tenantId = $request->attributes->getString('tenant_id');

    $description = $descriptions->describe($tenantId, $connection);

    abort_unless($description->isAvailable(), 404);

    return response($description->body, 200, [
        'Content-Type'  => $description->contentType,
        'Cache-Control' => 'public, max-age=3600',
    ]);
})->name('sso.metadata');
// @snippet-end service-provider-metadata-route
