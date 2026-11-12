<?php

declare(strict_types = 1);

/*
 * The import endpoint of `docs/guides/saml-metadata.md`, given `$input`.
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
