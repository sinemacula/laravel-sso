<?php

declare(strict_types = 1);

/*
 * The enable step of `docs/guides/saml-connections.md` (SSO-2.11, SSO-12.5), as
 * the application's administration screen runs it for the tenant's SAML
 * connection, given the tenant, the connection's id and the acting identity:
 * the package enables the connection, whether or not it is complete, and
 * answers the result, for the screen to turn into its response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\SamlConnections;

use SineMacula\Laravel\Sso\Connections\ConnectionService;
use Tests\Integration\Examples\Clients;

/**
 * @var array{
 *     tenant: \Tests\Integration\Examples\SamlConnections\Tenant,
 *     connection_id: string,
 *     caller: \SineMacula\Laravel\Sso\Identities\Caller
 * } $input
 */
$tenant       = $input['tenant'];
$connectionId = $input['connection_id'];
$caller       = $input['caller'];

$client = Clients::browser();
// @snippet-start saml-connections-enable
$result = app(ConnectionService::class)->enable($tenant->id, $connectionId, $client, $caller);
// @snippet-end saml-connections-enable
return $result;
