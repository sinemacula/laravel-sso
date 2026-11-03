<?php

declare(strict_types = 1);

/*
 * The endpoint of `docs/guides/saml-metadata.md` that has a connection follow
 * its metadata (SSO-2.8, SSO-11.12, SSO-12.5), as the application's
 * administration screen runs it, given the tenant, the connection, the
 * certificate of whoever signs the provider's metadata and the acting
 * identity: the package saves the metadata URL, which alone refreshes nothing,
 * then trusts the certificate as a metadata signing anchor, which turns the
 * scheduled refresh on and makes the first one due at once. It answers the two
 * results, in that order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\SamlMetadata;

/**
 * @var array{
 *     tenant: \Tests\Integration\Examples\SamlMetadata\Tenant,
 *     connection: \SineMacula\Laravel\Sso\Connections\ConnectionSummary,
 *     anchor: string,
 *     actor: \SineMacula\Laravel\Sso\Administration\ActingIdentity
 * } $input
 */
$tenant     = $input['tenant'];
$connection = $input['connection'];
$anchor     = $input['anchor'];
$actor      = $input['actor'];

// @snippet-start saml-metadata-follow
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;

$updated = app(ConnectionService::class)->update($tenant->id, $connection->id, ['settings' => [
    'metadata_url' => 'https://idp.example.com/metadata.xml',
]], $actor);

// With the provider's or the federation's signing certificate as an anchor,
// that is all it takes.
$anchored = app(KeyService::class)->trustCertificate($tenant->id, $connection->id, $anchor, $actor, KeyUse::METADATA_SIGNING);
// @snippet-end saml-metadata-follow
return [$updated, $anchored];
