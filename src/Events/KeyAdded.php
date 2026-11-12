<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;

/**
 * A service provider key pair or a trusted identity provider certificate was
 * added to a connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class KeyAdded implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  string  $keyId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  string  $fingerprint
     * @param  ?\Carbon\CarbonImmutable  $notAfter
     */
    public function __construct(

        /** Who made the change, and to which connection. */
        public EventContext $context,

        /** The id of the key or certificate. */
        public string $keyId,

        /** What the key or certificate is for. */
        public KeyUse $use,

        /** Where a service provider key starts in its rotation; `null` for a certificate. */
        public ?KeyState $state,

        /** Its lower-case hex SHA-256 fingerprint. */
        public string $fingerprint,

        /** When its certificate's validity ends; `null` without a certificate. */
        public ?CarbonImmutable $notAfter,
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
