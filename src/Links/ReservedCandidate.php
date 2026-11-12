<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The identity a completion reserved a link for, and its reservation.
 *
 * Never use it as the resolved identity: only its bound redemption makes it
 * one.
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
