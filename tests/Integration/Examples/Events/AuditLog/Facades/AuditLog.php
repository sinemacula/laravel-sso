<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Facades;

use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * A stand-in for `laravel-audit-log`'s real `Facades\AuditLog`, which this
 * package does not install, with the exact signature of the `map()` the guide
 * calls in a service provider's `boot()` (`docs/guides/events.md`): every event
 * of the class or interface, but those excepted, is handed to the mapper the
 * container resolves with a new `PendingRecord`, and each record it returns is
 * kept. `recorded()` and `forget()` are the stand-in's own, for a test; the
 * sibling writes each record to its store instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuditLog
{
    /** @var list<\SineMacula\Laravel\AuditLog\Records\PendingRecord> Each record a mapper returned, in order. */
    private static array $recorded = [];

    /**
     * Map every event of the class or interface, but those excepted, through
     * the mapper.
     *
     * @param  string  $classOrInterface
     * @param  string  $mapper
     * @param  list<string>  $except
     * @return void
     */
    public static function map(string $classOrInterface, string $mapper, array $except = []): void
    {
        Event::listen($classOrInterface, static function (object $event) use ($mapper, $except): void {

            $resolved = app($mapper);

            if (in_array($event::class, $except, true) || !$resolved instanceof EventMapper) {
                return;
            }

            $record = $resolved->map($event, new PendingRecord);

            if ($record === null) {
                return;
            }

            self::$recorded[] = $record;
        });
    }

    /**
     * Each record a mapper returned, in order.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Records\PendingRecord>
     */
    public static function recorded(): array
    {
        return self::$recorded;
    }

    /**
     * Forget every record kept.
     *
     * @return void
     */
    public static function forget(): void
    {
        self::$recorded = [];
    }
}
