<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Events;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\Sso\Events\FlowFailed;

/**
 * The `laravel-audit-log` mapper of `docs/guides/events.md`, against the
 * stand-ins in `Events/AuditLog`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoAuditMapper implements EventMapper
{
    // @snippet-start audit-mapper
    /**
     * The record of a failed flow, or `null` to skip any other event.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    #[\Override]
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord
    {
        if (!$event instanceof FlowFailed) {
            return null;
        }

        $context = $event->context()->toArray();

        $record->event('sso.flow_failed')
            ->failed($event->reason->value)
            ->withProperties(['flow' => $event->flow->value, 'application' => $context['application']]);

        if ($context['identity_morph_class'] !== null && $context['identity_id'] !== null) {
            $record->by(Reference::of($context['identity_morph_class'], $context['identity_id']));
        }

        // The tenant, under the type your application refers to its tenants by
        $tenant = $context['tenant_id'] ?? $context['connection_tenant_id'];

        if ($tenant !== null) {
            $record->forTenant(Reference::of('tenant', $tenant));
        }

        if ($context['request_reference'] !== null) {
            $record->correlatedWith("sso:{$context['connection_id']}:{$context['request_reference']}");
        }

        return $record;
    }
    // @snippet-end audit-mapper
}
