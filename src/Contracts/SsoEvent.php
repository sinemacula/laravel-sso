<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Events\EventContext;

/**
 * Every event the package dispatches implements this contract, so one listener
 * on it receives them all and attributes each the same way (SSO-9.6, SSO-10.4).
 *
 * Events report only: nothing that must happen for security depends on a
 * listener (SSO-10.5). They are dispatched after the transaction that caused
 * them commits, and never when it rolls back, except the unlinked-result event,
 * which is synchronous by design (SSO-8.6).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SsoEvent
{
    /**
     * Who and what the event is about.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    public function context(): EventContext;
}
