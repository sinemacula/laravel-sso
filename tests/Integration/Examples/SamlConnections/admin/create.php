<?php

declare(strict_types = 1);

/*
 * The create step of `docs/guides/saml-connections.md` (SSO-2.3, SSO-2.11,
 * SSO-12.5), as the application's administration screen runs it for the
 * tenant, given the tenant and the acting identity: the package creates the
 * tenant's SAML connection, disabled, with the identity provider's entity id
 * and single sign-on URL the organisation's administrator gave, and answers the
 * result for the screen to turn into its response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\SamlConnections;

/**
 * @var array{
 *     tenant: \Tests\Integration\Examples\SamlConnections\Tenant,
 *     actor: \SineMacula\Laravel\Sso\Administration\ActingIdentity
 * } $input
 */
$tenant = $input['tenant'];
$actor  = $input['actor'];

// @snippet-start saml-connections-create
use SineMacula\Laravel\Sso\Connections\ConnectionService;

$result = app(ConnectionService::class)->create(
    tenantId: $tenant->id,
    protocol: 'saml2',
    displayName: 'Acme Entra ID',
    settings: [
        'idp_entity_id'  => 'https://sts.windows.net/0000-1111/',
        'sso_url'        => 'https://login.microsoftonline.com/0000-1111/saml2',
        'sso_binding'    => 'http_redirect',
        'name_id_format' => 'persistent',
    ],
    actor: $actor,
);
// @snippet-end saml-connections-create
return $result;
