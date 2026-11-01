<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;

/**
 * A key of the service provider's own was made current (SSO-2.7, SSO-10.3); the
 * key it replaced, when there was one, is now retiring, still accepted for
 * decryption until its overlap ends.
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
final readonly class KeyMadeCurrent implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  string  $keyId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  string  $fingerprint
     * @param  ?string  $previousKeyId
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

        /** The id of the key it replaced, now retiring; `null` when there was none. */
        public ?string $previousKeyId,
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
