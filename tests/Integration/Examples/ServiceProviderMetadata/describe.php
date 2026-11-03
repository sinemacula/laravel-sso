<?php

declare(strict_types = 1);

/*
 * The description of `docs/guides/service-provider-metadata.md` (SSO-5.9,
 * SSO-12.5), as an application asks for it, given the tenant and the
 * connection: what an administrator registers at the identity provider, with
 * its content type, or why the connection cannot be described. It answers what
 * it read, for the example to assert.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

/** @var array{tenant_id: string, connection_id: string} $input */
$tenantId     = $input['tenant_id'];
$connectionId = $input['connection_id'];

// @snippet-start service-provider-describe
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;

$description = app(ServiceProviderDescriptions::class)->describe($tenantId, $connectionId);

if ($description->isAvailable()) {
    $contentType = $description->contentType; // 'application/samlmetadata+xml'
    $metadata    = $description->body;        // the metadata XML
} else {
    $reason = $description->reason; // FailureReason::CONNECTION_UNAVAILABLE or PROTOCOL_UNAVAILABLE
}
// @snippet-end service-provider-describe
return [
    'content_type' => $contentType ?? null,
    'metadata'     => $metadata    ?? null,
    'reason'       => $reason      ?? null,
];
