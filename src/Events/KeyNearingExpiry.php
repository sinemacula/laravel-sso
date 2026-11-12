<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;

/**
 * A key's or certificate's validity is within a configured threshold or has
 * ended; expiry is reported, never enforced.
 *
 * Sent at least once per threshold: a listener that must act once keeps its own
 * record of (`keyId`, `thresholdDays`).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class KeyNearingExpiry implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  string  $keyId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  string  $fingerprint
     * @param  \Carbon\CarbonImmutable  $notAfter
     * @param  int  $thresholdDays
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

        /** When its certificate's validity ends. */
        public CarbonImmutable $notAfter,

        /** The most urgent threshold reached, in days; 0 once validity has ended. */
        public int $thresholdDays,
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
