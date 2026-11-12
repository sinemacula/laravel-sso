<?php

declare(strict_types = 1);

/*
 * The administration screen's save of an accepted proposal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\OidcConnections;

use Tests\Integration\Examples\Clients;

/**
 * @var array{
 *     tenant: \Tests\Integration\Examples\OidcConnections\Tenant,
 *     connection: \SineMacula\Laravel\Sso\Connections\ConnectionSummary,
 *     proposed: \SineMacula\Laravel\Sso\Metadata\ProposedOidcSettings,
 *     client_id: string,
 *     secret: string,
 *     caller: \SineMacula\Laravel\Sso\Identities\Caller
 * } $input
 */
$tenant     = $input['tenant'];
$connection = $input['connection'];
$proposed   = $input['proposed'];
$clientId   = $input['client_id'];
$secret     = $input['secret'];
$caller     = $input['caller'];

$client = Clients::browser();
// @snippet-start oidc-connections-save
use SineMacula\Laravel\Sso\Connections\ImportSaver;

$result = app(ImportSaver::class)->save($tenant->id, $connection->id, [
    'settings' => [...$proposed->settings(), 'client_id' => $clientId, 'client_secret' => $secret],
], $proposed->fetch(), $client, $caller);
// @snippet-end oidc-connections-save
return $result;
