<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A session was established in an enforcing tenant under an exemption.
 *
 * Its context's `connectionTenantId` is the enforcing tenant and `tenantId` the
 * tenant the session acts in.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExemptionUsed implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  ?string  $enforcementVersion
     */
    public function __construct(

        /** Who was exempted, from which tenant's enforcement, and where. */
        public EventContext $context,

        /** The version of the enforcement the identity was exempted from. */
        public ?string $enforcementVersion,
    ) {}

    /**
     * Return who and what the event concerns.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
