<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;

/**
 * A key's or certificate's validity has come within a configured threshold, or
 * has ended (SSO-2.6, SSO-11.12, SSO-10.3). The expiry is reported, never
 * enforced: trust comes from the configured certificate, not its dates.
 *
 * The report sends it at least once for the most urgent threshold it finds
 * reached, skipping any it has passed, so a listener may see one twice, and a
 * listener that must act once keeps its own record of (`keyId`,
 * `thresholdDays`). It is dispatched outside any transaction. Its context names
 * the connection, its tenant and protocol, and the acting identity as the
 * application passed it (SSO-10.4), and the key's public identifiers; the
 * acting identity is `null` when the report runs on a schedule. It reports
 * only, and holds no secret, private key or setting value; it crosses a queue
 * as it is.
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

        /** What it is for: one of the service provider's own key pairs, or a trusted identity provider certificate. */
        public KeyUse $use,

        /** Its lower-case hex SHA-256 fingerprint, the public identifier an administrator compares. */
        public string $fingerprint,

        /** When its certificate's validity ends. */
        public CarbonImmutable $notAfter,

        /** The most urgent threshold reached, in days before the end of validity: 0 once it has ended. */
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
