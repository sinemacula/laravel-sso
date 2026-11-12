<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * A stand-in for `laravel-audit-log`'s `Contracts\EventMapper`, with its exact
 * signature.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface EventMapper
{
    /**
     * Fill the event's record and return it, or `null` to skip the event.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord;
}
