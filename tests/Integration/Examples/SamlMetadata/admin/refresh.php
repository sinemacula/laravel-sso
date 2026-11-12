<?php

declare(strict_types = 1);

/*
 * The refresh-now endpoint of `docs/guides/saml-metadata.md`, given `$input`.
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
 *     caller: \SineMacula\Laravel\Sso\Identities\Caller
 * } $input
 */
$tenant     = $input['tenant'];
$connection = $input['connection'];
$caller     = $input['caller'];

$client = Clients::browser();
// @snippet-start saml-metadata-refresh-now
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;

$result = app(MetadataRefresher::class)->refreshNow($tenant->id, $connection->id, $caller, $client);

if ($result->outcome === RefreshOutcome::RATE_LIMITED) {
    return back()->withErrors(['metadata' => "Try again in {$result->retryAfter} seconds."]);
}

$outcome = $result->outcome;         // RefreshOutcome::REFRESHED, FAILED, CONFLICT, IN_PROGRESS or REFUSED
$changed = $result->changedSettings; // ['sso_url', 'idp_signing_certificates'], say
// @snippet-end saml-metadata-refresh-now
return ['result' => $result, 'outcome' => $outcome, 'changed' => $changed];
