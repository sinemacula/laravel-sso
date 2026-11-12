<?php

declare(strict_types = 1);

/*
 * The save endpoint of `docs/guides/saml-metadata.md`, given `$input` for an
 * accepted proposal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\SamlMetadata;

use Tests\Integration\Examples\Clients;

/**
 * @var array{
 *     tenant: \Tests\Integration\Examples\SamlMetadata\Tenant,
 *     connection: \SineMacula\Laravel\Sso\Connections\ConnectionSummary,
 *     proposed: \SineMacula\Laravel\Sso\Metadata\ProposedSettings,
 *     caller: \SineMacula\Laravel\Sso\Identities\Caller
 * } $input
 */
$tenant     = $input['tenant'];
$connection = $input['connection'];
$proposed   = $input['proposed'];
$caller     = $input['caller'];

$client = Clients::browser();
// @snippet-start saml-metadata-save
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ImportSaver;
use SineMacula\Laravel\Sso\Keys\KeyService;

$changes = ['settings' => $proposed->settings()];
$fetch   = $proposed->fetch(); // null for metadata given as XML

$saved = $fetch === null
    ? app(ConnectionService::class)->update($tenant->id, $connection->id, $changes, $client, $caller)
    : app(ImportSaver::class)->save($tenant->id, $connection->id, $changes, $fetch, $client, $caller);

if (!$saved->isSucceeded()) {
    return back()->withErrors(['metadata' => $saved->reason?->value]);
}

foreach ($proposed->signingCertificates() as $certificate) {
    app(KeyService::class)->trustCertificate($tenant->id, $connection->id, $certificate['certificate'], $client, $caller);
}
// @snippet-end saml-metadata-save
return $saved;
