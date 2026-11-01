<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How a driver started an authorisation request (SSO-5.1): with the navigation
 * that sends the browser to the identity provider and what the request must
 * keep to complete it, or refused with a reason.
 *
 * What the request keeps is typed, never a free-form map: the SAML
 * `AuthnRequest` id `InResponseTo` must equal (SSO-5.3, SSO-6.6), the issuer
 * the response must come from, and whether that issuer must return `iss`
 * (SSO-7.1). The authorisation request pipeline stores each, and hands them
 * back to the driver in the `ConsumedRequest`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Start
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Navigation  $navigation
     * @param  ?string  $samlRequestId
     * @param  ?string  $expectedIssuer
     * @param  bool  $issuerRequired
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** Where the browser goes, for a started request. */
        public ?Navigation $navigation,

        /** The SAML `AuthnRequest` id, for a started SAML request. */
        public ?string $samlRequestId,

        /** The issuer the response must come from, for a started request. */
        public ?string $expectedIssuer,

        /** Whether the response must carry `iss` (RFC 9207), for a started OIDC request. */
        public bool $issuerRequired,

        /** Why the request could not start, for a refused one. */
        public ?FailureReason $reason,
    ) {}

    /**
     * The request started: the browser goes where the navigation leads, and the
     * authorisation request keeps what is given.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Navigation  $navigation
     * @param  ?string  $samlRequestId
     * @param  ?string  $expectedIssuer
     * @param  bool  $issuerRequired
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function navigate(Navigation $navigation, ?string $samlRequestId = null, ?string $expectedIssuer = null, bool $issuerRequired = false): self
    {
        if ($samlRequestId === '' || $expectedIssuer === '') {
            throw new \InvalidArgumentException('A started request\'s SAML request id and expected issuer are each non-empty when given.');
        }

        if ($samlRequestId !== null && strlen($samlRequestId) > Correlation::MAX_REQUEST_ID_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A SAML request id is at most %d bytes.', Correlation::MAX_REQUEST_ID_LENGTH));
        }

        return new self($navigation, $samlRequestId, $expectedIssuer, $issuerRequired, null);
    }

    /**
     * The request could not start, for the reason given.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self(null, null, null, false, $reason);
    }

    /**
     * Whether the request started.
     *
     * @return bool
     */
    public function isNavigating(): bool
    {
        return $this->navigation !== null;
    }

    /**
     * Whether the request was refused.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->reason !== null;
    }
}
