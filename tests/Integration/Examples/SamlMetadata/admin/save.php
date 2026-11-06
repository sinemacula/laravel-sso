<?php

declare(strict_types = 1);

/*
 * The save endpoint of `docs/guides/saml-metadata.md` (SSO-2.8, SSO-2.11,
 * SSO-12.5), as the application's administration screen runs it once the
 * administrator has compared the fingerprints and accepted a proposal, given
 * the tenant, the connection, the proposal and the acting identity: a proposal
 * from a fetch is saved with the fetch it came from, one from XML as by hand,
 * each asking the freshness contract; a refused save goes back with its reason,
 * and otherwise every signing certificate proposed is trusted. It answers the
 * save's result, for the endpoint to turn into its response.
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
 *     actor: \SineMacula\Laravel\Sso\Administration\ActingIdentity
 * } $input
 */
$tenant     = $input['tenant'];
$connection = $input['connection'];
$proposed   = $input['proposed'];
$actor      = $input['actor'];

$client = Clients::browser();
// @snippet-start saml-metadata-save
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ImportSaver;
use SineMacula\Laravel\Sso\Keys\KeyService;

$changes = ['settings' => $proposed->settings()];
$fetch   = $proposed->fetch(); // null for metadata given as XML

$saved = $fetch === null
    ? app(ConnectionService::class)->update($tenant->id, $connection->id, $changes, $client, $actor)
    : app(ImportSaver::class)->save($tenant->id, $connection->id, $changes, $fetch, $client, $actor);

if (!$saved->isSucceeded()) {
    return back()->withErrors(['metadata' => $saved->reason?->value]);
}

foreach ($proposed->signingCertificates() as $certificate) {
    app(KeyService::class)->trustCertificate($tenant->id, $connection->id, $certificate['certificate'], $client, $actor);
}
// @snippet-end saml-metadata-save
return $saved;
