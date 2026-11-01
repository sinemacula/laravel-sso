<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;

/**
 * A key or certificate was added to a connection (SSO-2.6, SSO-2.7, SSO-10.3):
 * a key pair of the service provider's own, generated as `next` (or `current`
 * when the connection had no key of that use), or a signing certificate of the
 * identity provider the connection now trusts.
 *
 * Dispatched after the transaction that made the change commits, and never when
 * it rolls back (SSO-10.5). Its context names the connection, its tenant and
 * protocol, and the acting identity as the application passed it (SSO-10.4),
 * and the key's public identifiers. It reports only, and holds no secret,
 * private key or setting value; it crosses a queue as it is.
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

        /** What it is for: one of the service provider's own key pairs, or a trusted identity provider certificate. */
        public KeyUse $use,

        /** Where a key of the service provider's own starts in its rotation; `null` for a trusted certificate. */
        public ?KeyState $state,

        /** Its lower-case hex SHA-256 fingerprint, the public identifier an administrator compares. */
        public string $fingerprint,

        /** When its certificate's validity ends, reported and never enforced; `null` without a certificate. */
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
