<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * What a handoff code was bound to at completion, as its redeemer read it from
 * its own store (SSO-8.5, SSO-8.8, SSO-9.9): the identity and the link the
 * result resolved to, the identity and the session the flow was started for,
 * and the reservation it holds with the handoff's opaque reference. The
 * package's redemption builds one from its code's row; an adapter that redeems
 * its own codes builds one from what its issuer stored, and passes it to
 * `Handoffs\HandoffRecheck`.
 *
 * It holds opaque references, never a code, a digest, a subject or a secret.
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
     */
    public function __construct(

        /** The identity the result's link resolved to at completion, if any. */
        public ?IdentityReference $linkedIdentity = null,

        /** The link the result observed at completion, active or suspended, if any. */
        public ?string $linkId = null,

        /** The identity a `link` or `reauthenticate` flow was started for. */
        public ?IdentityReference $identity = null,

        /** The session a `reauthenticate` flow was started on. */
        public ?string $sessionId = null,

        /** The reservation the code holds, if any. */
        public ?string $reservationId = null,

        /** The code's opaque reference, which its reservation holds. */
        public ?string $handoffReference = null,
    ) {}
}
