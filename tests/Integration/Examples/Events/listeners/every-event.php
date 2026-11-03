<?php

declare(strict_types = 1);

/*
 * The listener on every package event of `docs/guides/events.md` (SSO-9.6,
 * SSO-12.5), as an application's service provider registers it in `boot()`:
 * one listener on the `SsoEvent` contract, which writes each event's context
 * record to the application's `audit` log channel under the event's name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

// @snippet-start every-event-listener
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;

Event::listen(SsoEvent::class, static function (SsoEvent $event): void {
    Log::channel('audit')->info(class_basename($event), $event->context()->toArray());
});
// @snippet-end every-event-listener
