<?php

declare(strict_types = 1);

/*
 * The starts for a signed-in caller of `docs/guides/starting-a-flow.md`
 * (SSO-2.12, SSO-5.1, SSO-5.10, SSO-12.5), as the application's start endpoint
 * for its own authenticated user runs them, given the connection and the
 * challenge the client sends: the caller is the application's user, named by
 * its morph class and key, on the session the application's own authentication
 * holds, never the request body's. The package starts a `link` once the
 * freshness contract answers `fresh` for that caller, and a `reauthenticate`
 * once the identity is signed in through the connection on the session.
 * `StartingAFlowExampleTest` runs it and asserts both, and each refusal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;

/** @var array{user: \Tests\Integration\Examples\StartingAFlow\User, connection: string, code_challenge: string, session: string, client: \SineMacula\Laravel\Sso\Http\ClientContext} $input */
$requests     = app(AuthorizationRequestService::class);
$user         = $input['user'];
$connectionId = $input['connection'];
$challenge    = $input['code_challenge'];
$sessionId    = $input['session'];
$client       = $input['client'];

// @snippet-start start-for-the-caller
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

$caller = new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $sessionId);

$linking          = $requests->start('web', Purpose::LINK, $connectionId, $client, $challenge, $caller);
$reauthenticating = $requests->start('web', Purpose::REAUTHENTICATE, $connectionId, $client, $challenge, $caller);
// @snippet-end start-for-the-caller
return [$linking, $reauthenticating];
