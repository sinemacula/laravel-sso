<?php

declare(strict_types = 1);

/*
 * The key expiry listener of `docs/guides/operations.md`, as a service
 * provider's `boot()` registers it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\Operations;

// @snippet-start key-nearing-expiry-listener
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;

Event::listen(KeyNearingExpiry::class, function (KeyNearingExpiry $event): void {
    SecurityTeam::notify(new CertificateExpiring($event->context()->connectionId, $event->fingerprint, $event->notAfter, $event->thresholdDays));
});
// @snippet-end key-nearing-expiry-listener
