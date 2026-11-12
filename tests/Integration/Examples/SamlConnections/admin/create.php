<?php

declare(strict_types = 1);

/*
 * The create step of `docs/guides/saml-connections.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\SamlConnections;

use Tests\Integration\Examples\Clients;

/**
 * @var array{
 *     tenant: \Tests\Integration\Examples\SamlConnections\Tenant,
 *     caller: \SineMacula\Laravel\Sso\Identities\Caller
 * } $input
 */
$tenant = $input['tenant'];
$caller = $input['caller'];

$client = Clients::browser();
// @snippet-start saml-connections-create
use SineMacula\Laravel\Sso\Connections\ConnectionService;

$result = app(ConnectionService::class)->create(
    tenantId: $tenant->id,
    protocol: 'saml2',
    displayName: 'Acme Entra ID',
    client: $client,
    settings: [
        'idp_entity_id'  => 'https://sts.windows.net/0000-1111/',
        'sso_url'        => 'https://login.microsoftonline.com/0000-1111/saml2',
        'sso_binding'    => 'http_redirect',
        'name_id_format' => 'persistent',
    ],
    caller: $caller,
);
// @snippet-end saml-connections-create
return $result;
