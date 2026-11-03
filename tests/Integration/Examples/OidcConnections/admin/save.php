<?php

declare(strict_types = 1);

/*
 * The save endpoint of `docs/guides/oidc-connections.md` (SSO-2.8, SSO-2.11,
 * SSO-12.5), as the application's administration screen runs it once the
 * administrator has accepted a proposal, given the tenant, the connection, the
 * proposal, the client the form names and the acting identity: the package
 * asks the freshness contract as `sso.connection.trust`, makes the update the
 * connection service would, and stamps the fetch the proposal came from. It
 * answers the result, for the endpoint to turn into its response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\OidcConnections;

/**
 * @var array{
 *     tenant: \Tests\Integration\Examples\OidcConnections\Tenant,
 *     connection: \SineMacula\Laravel\Sso\Connections\ConnectionSummary,
 *     proposed: \SineMacula\Laravel\Sso\Metadata\ProposedOidcSettings,
 *     client_id: string,
 *     secret: string,
 *     actor: \SineMacula\Laravel\Sso\Administration\ActingIdentity
 * } $input
 */
$tenant     = $input['tenant'];
$connection = $input['connection'];
$proposed   = $input['proposed'];
$clientId   = $input['client_id'];
$secret     = $input['secret'];
$actor      = $input['actor'];

// @snippet-start oidc-connections-save
use SineMacula\Laravel\Sso\Connections\ImportSaver;

$result = app(ImportSaver::class)->save($tenant->id, $connection->id, [
    'settings' => [...$proposed->settings(), 'client_id' => $clientId, 'client_secret' => $secret],
], $proposed->fetch(), $actor);
// @snippet-end oidc-connections-save
return $result;
