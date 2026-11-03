<?php

declare(strict_types = 1);

/*
 * The import endpoint of `docs/guides/oidc-connections.md` (SSO-2.8, SSO-2.11,
 * SSO-12.5), as the application's administration screen runs it for the
 * tenant's OIDC connection, given the tenant and the connection: the package
 * fetches the issuer's discovery document and keys and answers what they
 * propose, writing and trusting nothing. A rate limited import goes back with
 * the wait, and a refused one with its reason; a proposal is answered with what
 * the screen shows the administrator, for the endpoint to render.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\OidcConnections;

/** @var array{tenant: \Tests\Integration\Examples\OidcConnections\Tenant, connection: \SineMacula\Laravel\Sso\Connections\ConnectionSummary} $input */
$tenant     = $input['tenant'];
$connection = $input['connection'];

// @snippet-start oidc-connections-import
use SineMacula\Laravel\Sso\Metadata\DiscoveryImporter;

$result = app(DiscoveryImporter::class)->import(
    tenantId: $tenant->id,
    issuer: 'https://login.example.com/tenant-a',
    connectionId: $connection->id, // or leave it out before the connection exists
);

if ($result->isRateLimited()) {
    return back()->withErrors(['issuer' => "Try again in {$result->retryAfter} seconds."]);
}

if (!$result->isProposed()) {
    return back()->withErrors(['issuer' => $result->reason?->value]);
}

$proposed = $result->proposed;

$settings    = $proposed->settings();
$authMethods = $proposed->authMethods();
$keys        = $proposed->keys();
// @snippet-end oidc-connections-import
return ['proposed' => $proposed, 'settings' => $settings, 'auth_methods' => $authMethods, 'keys' => $keys];
