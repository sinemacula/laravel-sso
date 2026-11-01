<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A response passed every check and its verified result was built (SSO-8.1,
 * SSO-10.1, SSO-9.6): fired at completion, before any handoff is redeemed, so
 * an audit sink can correlate it with the redemption by the connection and the
 * request's public reference instead of counting a sign-in twice.
 *
 * Dispatched after the completion's transaction commits, and never when it
 * rolls back (SSO-10.5). Its context names the connection, its tenant and
 * protocol, the application, the purpose, the request's public reference and,
 * when the result's link resolved, the identity (SSO-10.4). The result itself
 * is never carried: no subject, attribute or authentication context, and
 * crosses a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ResultVerified implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     */
    public function __construct(

        /** Who and what the result concerns. */
        public EventContext $context,
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
