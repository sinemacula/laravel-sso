<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;

/**
 * A key or certificate was retired and removed from a connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class KeyRetired implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  string  $keyId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  string  $fingerprint
     */
    public function __construct(

        /** Who made the change, and to which connection. */
        public EventContext $context,

        /** The id of the key or certificate. */
        public string $keyId,

        /** What the key or certificate is for. */
        public KeyUse $use,

        /** Its lower-case hex SHA-256 fingerprint. */
        public string $fingerprint,
    ) {}

    /**
     * Return who and what the change concerned.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
