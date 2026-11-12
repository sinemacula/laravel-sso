<?php

declare(strict_types = 1);

/*
 * The anchor endpoint of `docs/guides/saml-metadata.md`, given `$input`.
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
// @snippet-start saml-metadata-anchor
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;

$trusted = app(KeyService::class)->trustCertificate($tenant->id, $connection->id, $anchor, $client, $caller, KeyUse::METADATA_SIGNING);
// @snippet-end saml-metadata-anchor
return $trusted;
