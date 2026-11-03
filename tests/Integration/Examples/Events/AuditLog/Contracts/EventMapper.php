<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * A stand-in for `laravel-audit-log`'s real `Contracts\EventMapper`, which this
 * package does not install, with its exact signature: what fills the record of
 * an event an application maps (`docs/guides/events.md`), or skips it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface EventMapper
{
    /**
     * Fill the record of the event and return it, or return `null` to skip the
     * event.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord;
}
