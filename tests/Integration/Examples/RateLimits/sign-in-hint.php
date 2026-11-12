<?php

declare(strict_types = 1);

/*
 * The application's own sign-in hint of `docs/guides/rate-limits.md`, counted
 * through the package's limiter so it cannot be used to probe organisations.
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
