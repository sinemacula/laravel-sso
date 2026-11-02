<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The identity a completion reserved a link for (SSO-8.8), and the reservation
 * that holds it. It travels apart from the state's resolved identity, and never
 * in its place: a reservation resolves no sign-in, and only its bound
 * redemption ever makes the candidate the result's identity. It never reaches
 * an event or a handoff grant's linked identity.
 *
 * It holds opaque references and a time, never a subject, an email or a secret.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ReservedCandidate
{
    /**
     * Constructor.
     *
     * @param  string  $reservationId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** The reservation's unique identity. */
        public string $reservationId,

        /** The identity the linking email matched. */
        public IdentityReference $identity,

        /** When the reservation expires, as stored, and with it its handoff. */
        public CarbonImmutable $expiresAt,
    ) {}
}
