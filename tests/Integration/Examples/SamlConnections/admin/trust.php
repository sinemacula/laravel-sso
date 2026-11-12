<?php

declare(strict_types = 1);

/*
 * The trust step of `docs/guides/saml-connections.md`, run once the
 * administrator has compared the certificate's fingerprint.
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
 *     caller: \SineMacula\Laravel\Sso\Identities\Caller
 * } $input
 */
$keys           = $input['keys'];
$tenant         = $input['tenant'];
$connectionId   = $input['connection_id'];
$certificatePem = $input['certificate'];
$caller         = $input['caller'];

$client = Clients::browser();
// @snippet-start saml-connections-trust
$keys->trustCertificate($tenant->id, $connectionId, $certificatePem, $client, $caller);
// @snippet-end saml-connections-trust
return $keys->keys($tenant->id, $connectionId);
