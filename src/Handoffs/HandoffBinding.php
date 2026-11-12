<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * What a handoff code was bound to at completion, as its redeemer read it from
 * its store.
 *
 * A binding with no trust version is refused, so a store that keeps none fails
 * closed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class HandoffBinding
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $linkedIdentity
     * @param  ?string  $linkId
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @param  ?string  $reservationId
     * @param  ?string  $handoffReference
     * @param  ?int  $trustVersion
     */
    public function __construct(

        /** The identity the result's link resolved to at completion, if any. */
        public ?IdentityReference $linkedIdentity = null,

        /** The link the result observed at completion, if any. */
        public ?string $linkId = null,

        /** The identity a `link` or `reauthenticate` flow was started for. */
        public ?IdentityReference $identity = null,

        /** The session a `reauthenticate` flow was started on. */
        public ?string $sessionId = null,

        /** The reservation the code holds, if any. */
        public ?string $reservationId = null,

        /** The code's opaque reference, which its reservation holds. */
        public ?string $handoffReference = null,

        /** The trust version the code was issued under; `null` refuses it. */
        public ?int $trustVersion = null,
    ) {}
}
