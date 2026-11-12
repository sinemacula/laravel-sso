<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * An OIDC connection's JWKS was refetched because an ID token named an unknown
 * `kid`; a scheduled refresh reports `MetadataRefreshed` instead.
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
