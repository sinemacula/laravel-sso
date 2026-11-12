<?php

declare(strict_types = 1);

/*
 * The administration screen's discovery import, writing nothing.
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
