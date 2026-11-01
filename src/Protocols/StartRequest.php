<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * What a driver is given to start an authorisation request (SSO-5.1 to
 * SSO-5.4): the purpose, the application, the request's public reference, and
 * the protocol state the package generated for it (the random reference sent as
 * OIDC `state` or SAML `RelayState`, and for OIDC the nonce and the PKCE
 * verifier whose S256 challenge the driver sends).
 *
 * The protocol state is held as `Secrets\Secret` values, so it never reaches a
 * log, an exception or an event (SSO-9.8), and the request cannot be
 * serialised. The authorisation request pipeline (BL-32) builds it; a driver
 * only reads it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class StartRequest
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $state
     * @param  ?\SineMacula\Laravel\Sso\Secrets\Secret  $nonce
     * @param  ?\SineMacula\Laravel\Sso\Secrets\Secret  $codeVerifier
     */
    public function __construct(

        /** What the flow is for; `reauthenticate` forces fresh authentication. */
        public Purpose $purpose,

        /** The configured application the flow is for. */
        public string $application,

        /** The authorisation request's public reference. */
        public RequestReference $reference,

        /** The random reference sent as OIDC `state` or SAML `RelayState`, never the public reference. */
        public Secret $state,

        /** The OIDC nonce, for an OIDC request. */
        public ?Secret $nonce = null,

        /** The PKCE verifier the package uses with the identity provider, for an OIDC request; it never leaves the API. */
        public ?Secret $codeVerifier = null,
    ) {}
}
