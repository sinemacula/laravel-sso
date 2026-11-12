<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;

/**
 * Reads the `state` of an OpenID Connect callback from its raw `GET` query to
 * find the authorisation request it answers, validating nothing else.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallbackCorrelator
{
    /** @var string The only accepted method; `form_post` responses are refused. */
    private const string METHOD = 'GET';

    /** @var string The package's 256-bit state as unpadded base64url. */
    private const string STATE = '/^[A-Za-z0-9_-]{43}$/D';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits  $limits
     */
    public function __construct(

        /** The caps on the callback's parameters. */
        private OidcLimits $limits,
    ) {}

    /**
     * Read which request the callback names.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     *
     * @throws \InvalidArgumentException
     */
    public function correlate(SsoConnection $connection, CompletionRequest $request): Correlation
    {
        unset($connection);

        $state = $request->method === self::METHOD ? CallbackParameters::parse($request->query(), $this->limits)?->state() : null;

        return $state !== null && preg_match(self::STATE, $state) === 1 ? Correlation::solicited($state) : Correlation::uncorrelated();
    }
}
