<?php

declare(strict_types = 1);

/*
 * The starts for a signed-in caller of `docs/guides/starting-a-flow.md`; the
 * caller comes from the application's authentication, never the request.
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
