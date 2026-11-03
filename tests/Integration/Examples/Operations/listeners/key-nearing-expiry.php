<?php

declare(strict_types = 1);

/*
 * The key expiry listener of `docs/guides/operations.md` (SSO-2.6, SSO-11.12,
 * SSO-12.5), as an application's service provider registers it in `boot()`:
 * one listener on `KeyNearingExpiry`, which tells the application's security
 * team to rotate, with the connection, the key's fingerprint, the end of its
 * validity and the threshold it reached.
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
