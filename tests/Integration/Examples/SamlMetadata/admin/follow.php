<?php

declare(strict_types = 1);

/*
 * The follow endpoint of `docs/guides/saml-metadata.md`, given `$input`; it
 * answers the update's and the anchor's results.
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
 *     anchor: string,
 *     caller: \SineMacula\Laravel\Sso\Identities\Caller
 * } $input
 */
$tenant     = $input['tenant'];
$connection = $input['connection'];
$anchor     = $input['anchor'];
$caller     = $input['caller'];

$client = Clients::browser();
// @snippet-start saml-metadata-follow
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;

$updated = app(ConnectionService::class)->update($tenant->id, $connection->id, ['settings' => [
    'metadata_url' => 'https://idp.example.com/metadata.xml',
]], $client, $caller);

// With the provider's or the federation's signing certificate as an anchor,
// that is all it takes.
$anchored = app(KeyService::class)->trustCertificate($tenant->id, $connection->id, $anchor, $client, $caller, KeyUse::METADATA_SIGNING);
// @snippet-end saml-metadata-follow
return [$updated, $anchored];
