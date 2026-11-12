<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * What a driver is given to start an authorisation request, with the protocol
 * state the package generated for it held as secrets.
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

        /** The random OIDC `state` or SAML `RelayState`; not the public reference. */
        public Secret $state,

        /** The OIDC nonce, for an OIDC request. */
        public ?Secret $nonce = null,

        /** The PKCE verifier, for an OIDC request. */
        public ?Secret $codeVerifier = null,
    ) {}
}
