<?php

declare(strict_types = 1);

/*
 * The audit trail of `docs/guides/events.md` (SSO-10.4, SSO-12.5), as an
 * application's service provider registers it in `boot()`: one listener on the
 * connection and key administration events, which stores each as one of the
 * application's own `AuditEntry` rows, with the tenant, the connection, who
 * acted, what the event adds to its context, and the context's whole record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\Events;

// @snippet-start audit-trail-listener
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\ConnectionEnabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyMadeCurrent;
use SineMacula\Laravel\Sso\Events\KeyRetired;

Event::listen([
    ConnectionCreated::class,
    ConnectionUpdated::class,
    ConnectionEnabled::class,
    ConnectionDisabled::class,
    ConnectionDeleted::class,
    KeyAdded::class,
    KeyMadeCurrent::class,
    KeyRetired::class,
], static function (SsoEvent $event): void {
    $context = $event->context();
    $details = match (true) {
        $event instanceof ConnectionUpdated => ['changed' => $event->changedSettings],
        $event instanceof KeyAdded          => ['key_id' => $event->keyId, 'use' => $event->use->value, 'fingerprint' => $event->fingerprint],
        $event instanceof KeyMadeCurrent    => ['key_id' => $event->keyId, 'replaced' => $event->previousKeyId],
        $event instanceof KeyRetired        => ['key_id' => $event->keyId, 'fingerprint' => $event->fingerprint],
        default                             => [],
    };

    AuditEntry::create([
        'event'         => class_basename($event),
        'tenant_id'     => $context->connectionTenantId,
        'connection_id' => $context->connectionId,
        'actor_type'    => $context->actingIdentityMorphClass,
        'actor_id'      => $context->actingIdentityId,
        'details'       => $details,
        'context'       => $context->toArray(),
    ]);
});
// @snippet-end audit-trail-listener
