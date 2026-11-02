<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;

/**
 * Reads which authorisation request an OpenID Connect callback answers, by its
 * `state` (SSO-7.1), from the raw query before anything parses it, validating
 * nothing else.
 *
 * A callback is correlated only when it is a `GET` (a `form_post` response is
 * never accepted), its raw query passes `CallbackParameters::parse()`, so a
 * repeated, conflicting, array-shaped or oversized parameter is refused before
 * any request is looked up, and its `state` is exactly the 43 base64url
 * characters of the package's 256-bit state. Anything else is uncorrelated,
 * which the pipeline reports as `request_unknown` with no redirect target and
 * nothing consumed (SSO-5.7).
 *
 * It logs nothing and reads no other value of the query. It holds the limits
 * alone, read afresh on each call (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallbackCorrelator
{
    /** @var string The only method an authorisation response arrives by (`response_mode=query`). */
    private const string METHOD = 'GET';

    /** @var string The package's 256-bit state: exactly 43 base64url characters, with no padding. */
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
