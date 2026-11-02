<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * An OIDC connection's JWKS was refetched because an ID token named a `kid` it
 * did not hold (SSO-7.3, SSO-10.3): fetched from the connection's `jwks_uri`
 * within the refetch cooldown, validated whole, and stored in place of the keys
 * it held. It says how many keys the refetch added and how many it removed (a
 * key kept under its `kid` in another form counts as both), the connection's
 * JWKS version after it, and whether it changed the connection's trust: a key
 * removed or replaced does, which voids the flows in flight through it; keys
 * only added never do, so a refetch never voids the flow that asked for it. A
 * scheduled refresh of the discovery document and the JWKS is reported as
 * `MetadataRefreshed`.
 *
 * Dispatched after the transaction that stored the keys commits, and never when
 * it rolls back (SSO-10.5). Its context names the connection, its tenant and
 * protocol (SSO-10.4). It reports only, and holds no key, URL, token or other
 * value of the JWKS; it crosses a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class JwksRefreshed implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  int  $jwksVersion
     * @param  int  $keysAdded
     * @param  int  $keysRemoved
     * @param  bool  $trustChanged
     */
    public function __construct(

        /** Which connection's keys were refetched. */
        public EventContext $context,

        /** The connection's JWKS version after the refetch. */
        public int $jwksVersion,

        /** How many keys the refetch added. */
        public int $keysAdded,

        /** How many keys the refetch removed or replaced. */
        public int $keysRemoved,

        /** Whether the refetch removed or replaced a key, voiding the flows in flight. */
        public bool $trustChanged,
    ) {}

    /**
     * Return who and what the refetch concerned.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
