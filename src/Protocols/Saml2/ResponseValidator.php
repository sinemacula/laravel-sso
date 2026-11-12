<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;

/**
 * Validates a solicited SAML response against the request consumed for it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResponseValidator
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator  $validator
     */
    public function __construct(

        /** Holds the response to every rule of its profile. */
        private AssertionValidator $validator,
    ) {}

    /**
     * Validate the response against the consumed request.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \InvalidArgumentException
     */
    public function complete(SsoConnection $connection, Saml2Options $options, CompletionRequest $request, ConsumedRequest $consumed): Completion
    {
        return $this->validator->validate($connection, $options, $request, $consumed);
    }
}
