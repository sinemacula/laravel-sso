<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;

/**
 * Dispatched once for every refused authorisation request, SAML response, OIDC
 * callback and handoff redemption, with the flow and a machine-readable reason
 * (SSO-10.2). One refused operation fires exactly one, however many checks it
 * failed: the reason is the first that refused it.
 *
 * Carries as much context as the flow established before it was refused (the
 * connection once it was found, the request reference once the request was
 * read, the identity once it was resolved), and nothing else: no free-text
 * message, since a provider's diagnostic text goes to the logs, sanitised, and
 * never to an event. Never a secret, assertion, provider token, verifier,
 * handoff code, protocol state, raw payload or transport header (SSO-10.4).
 *
 * It holds a context of strings and two enums, so it crosses a queue as it is
 * and a queued listener receives what a synchronous one does.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FlowFailed implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    public function __construct(

        /** Who and what the refusal concerned, as far as the flow got. */
        public EventContext $context,

        /** The operation that was refused. */
        public Flow $flow,

        /** Machine-readable reason it was refused. */
        public FailureReason $reason,
    ) {}

    /**
     * Return who and what the refusal concerned.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
