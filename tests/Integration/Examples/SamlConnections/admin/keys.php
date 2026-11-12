<?php

declare(strict_types = 1);

/*
 * The keys step of `docs/guides/saml-connections.md`: the first key of each use
 * is made current at once.
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
