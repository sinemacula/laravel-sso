<?php

declare(strict_types = 1);

/*
 * The application's own sign-in hint of `docs/guides/rate-limits.md`
 * (SSO-11.8, SSO-12.5), given the request being served and the domain of the
 * email address typed: before it tells the person whether their organisation
 * signs in through SSO, which would let anyone probe an organisation, it counts
 * the attempt as an authorisation request against the client's IP address and
 * the email's domain, through the package's limiter, and answers what the
 * limiter decided, a refused attempt carrying the seconds to wait.
 * `RateLimitsExampleTest` runs it and asserts each decision.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

/** @var array{request: \Illuminate\Http\Request, domain: ?string} $input */
$request     = $input['request'];
$emailDomain = $input['domain'];

// @snippet-start attempt-limiter
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

$result = app(AttemptLimiter::class)->attempt(
    AttemptSubject::authorizationRequest(ClientContext::fromRequest($request), $emailDomain),
);
// @snippet-end attempt-limiter
return $result;
