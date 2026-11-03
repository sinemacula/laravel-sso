<?php

declare(strict_types = 1);

/*
 * The import endpoint of `docs/guides/saml-metadata.md` (SSO-2.8, SSO-2.11,
 * SSO-12.5), as the application's administration screen runs it for the
 * tenant's SAML connection, or before the connection exists, given the tenant
 * and the connection or `null`: the package fetches the provider's metadata and
 * answers the settings it proposes, writing and trusting nothing. A rate
 * limited import goes back with the wait, and a refused one with its reason; a
 * proposal is answered with what the screen shows the administrator, for the
 * endpoint to render.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\SamlMetadata;

/** @var array{tenant: \Tests\Integration\Examples\SamlMetadata\Tenant, connection: ?\SineMacula\Laravel\Sso\Connections\ConnectionSummary} $input */
$tenant     = $input['tenant'];
$connection = $input['connection'];

// @snippet-start saml-metadata-import
use SineMacula\Laravel\Sso\Metadata\MetadataImporter;

$result = app(MetadataImporter::class)->importUrl(
    tenantId: $tenant->id,
    connectionId: $connection?->id, // null before the connection exists
    url: 'https://idp.example.com/metadata.xml',
    entityId: 'https://idp.example.com/saml',
);

if ($result->isRateLimited()) {
    return back()->withErrors(['metadata' => "Try again in {$result->retryAfter} seconds."]);
}

$proposed = $result->proposed;

if ($proposed === null) {
    return back()->withErrors(['metadata' => $result->reason?->value]);
}

$settings   = $proposed->settings();               // the entity id, sign-on URL and binding
$signing    = $proposed->signingCertificates();    // each certificate with its fingerprint
$encryption = $proposed->encryptionCertificates(); // the same shape
$formats    = $proposed->nameIdFormats();          // the NameID formats the provider names
$validUntil = $proposed->validUntil();             // a CarbonImmutable, or null
// @snippet-end saml-metadata-import
return [
    'proposed'    => $proposed,
    'settings'    => $settings,
    'signing'     => $signing,
    'encryption'  => $encryption,
    'formats'     => $formats,
    'valid_until' => $validUntil,
];
