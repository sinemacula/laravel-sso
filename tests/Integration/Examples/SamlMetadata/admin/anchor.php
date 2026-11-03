<?php

declare(strict_types = 1);

/*
 * The anchor endpoint of `docs/guides/saml-metadata.md` (SSO-2.5, SSO-2.8,
 * SSO-12.5), as the application's administration screen runs it, given the
 * tenant, the connection, the certificate of whoever signs the provider's
 * metadata (the provider or its federation) and the acting identity: the
 * package trusts the certificate as a metadata signing anchor, asking the
 * freshness contract, so every import naming the connection, and every
 * refresh, must then be signed by it. It answers the result.
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

// @snippet-start saml-metadata-anchor
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;

$trusted = app(KeyService::class)->trustCertificate($tenant->id, $connection->id, $anchor, $actor, KeyUse::METADATA_SIGNING);
// @snippet-end saml-metadata-anchor
return $trusted;
