<?php

declare(strict_types = 1);

/*
 * The keys step of `docs/guides/saml-connections.md` (SSO-2.7, SSO-12.5), as
 * the application's administration screen runs it for the tenant's SAML
 * connection, given the tenant, the connection's id and the acting identity:
 * the package generates the service provider's signing key and encryption key,
 * each the first of its use and so made current at once. It answers the
 * connection's keys, for the screen to show.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\SamlConnections;

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
// @snippet-start saml-connections-keys
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;

$keys = app(KeyService::class);

$keys->addNext($tenant->id, $connectionId, KeyUse::SP_SIGNING, $client, caller: $caller);
$keys->addNext($tenant->id, $connectionId, KeyUse::SP_ENCRYPTION, $client, caller: $caller);
// @snippet-end saml-connections-keys
return $keys->keys($tenant->id, $connectionId);
