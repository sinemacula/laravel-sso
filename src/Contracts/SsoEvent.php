<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Events\EventContext;

/**
 * Implemented by every event the package dispatches, so one listener can take
 * them all.
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
