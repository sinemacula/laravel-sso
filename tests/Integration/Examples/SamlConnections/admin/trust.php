<?php

declare(strict_types = 1);

/*
 * The trust step of `docs/guides/saml-connections.md` (SSO-2.6, SSO-12.5), as
 * the application's administration screen runs it once the administrator has
 * compared the certificate's fingerprint with the one the identity provider's
 * administrator gave, given the key service, the tenant, the connection's id,
 * the PEM certificate and the acting identity: the package trusts the
 * certificate as the identity provider's signing certificate. It answers the
 * connection's keys, for the screen to show.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\SamlConnections;

use Tests\Integration\Examples\Clients;

/**
 * @var array{
 *     keys: \SineMacula\Laravel\Sso\Keys\KeyService,
 *     tenant: \Tests\Integration\Examples\SamlConnections\Tenant,
 *     connection_id: string,
 *     certificate: string,
 *     actor: \SineMacula\Laravel\Sso\Administration\ActingIdentity
 * } $input
 */
$keys           = $input['keys'];
$tenant         = $input['tenant'];
$connectionId   = $input['connection_id'];
$certificatePem = $input['certificate'];
$actor          = $input['actor'];

$client = Clients::browser();
// @snippet-start saml-connections-trust
$keys->trustCertificate($tenant->id, $connectionId, $certificatePem, $client, $actor);
// @snippet-end saml-connections-trust
return $keys->keys($tenant->id, $connectionId);
