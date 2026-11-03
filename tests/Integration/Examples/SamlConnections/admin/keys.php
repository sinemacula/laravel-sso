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

/**
 * @var array{
 *     tenant: \Tests\Integration\Examples\SamlConnections\Tenant,
 *     connection_id: string,
 *     actor: \SineMacula\Laravel\Sso\Administration\ActingIdentity
 * } $input
 */
$tenant       = $input['tenant'];
$connectionId = $input['connection_id'];
$actor        = $input['actor'];

// @snippet-start saml-connections-keys
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;

$keys = app(KeyService::class);

$keys->addNext($tenant->id, $connectionId, KeyUse::SP_SIGNING, actor: $actor);
$keys->addNext($tenant->id, $connectionId, KeyUse::SP_ENCRYPTION, actor: $actor);
// @snippet-end saml-connections-keys
return $keys->keys($tenant->id, $connectionId);
