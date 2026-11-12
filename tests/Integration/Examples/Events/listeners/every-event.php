<?php

declare(strict_types = 1);

/*
 * The every-event listener of `docs/guides/events.md`, as a service provider
 * registers it in `boot()`.
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
