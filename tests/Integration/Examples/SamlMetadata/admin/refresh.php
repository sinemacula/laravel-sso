<?php

declare(strict_types = 1);

/*
 * The refresh endpoint of `docs/guides/saml-metadata.md` (SSO-2.8, SSO-11.12,
 * SSO-12.5), as the application's administration screen runs it when an
 * administrator asks for a connection's metadata at once, given the tenant,
 * the connection and the acting identity: the package refreshes the connection
 * in the request, past its backoff and whatever the schedule does. A refresh
 * past the connection's metadata limit goes back with the wait; any other is
 * answered with its outcome and the settings it changed, for the endpoint to
 * render.
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
 *     actor: \SineMacula\Laravel\Sso\Administration\ActingIdentity
 * } $input
 */
$tenant     = $input['tenant'];
$connection = $input['connection'];
$actor      = $input['actor'];

$client = Clients::browser();
// @snippet-start saml-metadata-refresh-now
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;

$result = app(MetadataRefresher::class)->refreshNow($tenant->id, $connection->id, $actor, $client);

if ($result->outcome === RefreshOutcome::RATE_LIMITED) {
    return back()->withErrors(['metadata' => "Try again in {$result->retryAfter} seconds."]);
}

$outcome = $result->outcome;         // RefreshOutcome::REFRESHED, FAILED, CONFLICT, IN_PROGRESS or REFUSED
$changed = $result->changedSettings; // ['sso_url', 'idp_signing_certificates'], say
// @snippet-end saml-metadata-refresh-now
return ['result' => $result, 'outcome' => $outcome, 'changed' => $changed];
