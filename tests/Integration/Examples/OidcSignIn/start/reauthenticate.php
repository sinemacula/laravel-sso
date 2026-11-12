<?php

declare(strict_types = 1);

/*
 * The start endpoint's `reauthenticate` for a signed-in caller.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;

/** @var array{connection: string, code_challenge: ?string, identity: \SineMacula\Laravel\Sso\Identities\IdentityReference, session: string, client: \SineMacula\Laravel\Sso\Http\ClientContext} $input */
$connectionId  = $input['connection'];
$codeChallenge = $input['code_challenge'];
$identity      = $input['identity'];
$sessionId     = $input['session'];
$client        = $input['client'];

// @snippet-start oidc-start-reauthenticate
use SineMacula\Laravel\Sso\Identities\Caller;

$result = app(AuthorizationRequestService::class)->start(
    application: 'web',
    purpose: Purpose::REAUTHENTICATE,
    connectionId: $connectionId,
    client: $client,
    codeChallenge: $codeChallenge,
    caller: new Caller($identity, $sessionId),
);
// @snippet-end oidc-start-reauthenticate
return $result;
