<?php

declare(strict_types = 1);

/*
 * The reauthentication start of `docs/guides/oidc-sign-in.md` (SSO-5.4,
 * SSO-5.10, SSO-12.5), as the application's start endpoint for a signed-in
 * caller runs it, given the connection and the PKCE challenge the client
 * sends, and the identity and the session the application's own
 * authentication holds for the caller, never the request body's: the package
 * starts an OIDC `reauthenticate` that forces fresh authentication at the
 * provider, or refuses it when the identity is not signed in through the
 * connection on the session. `OidcSignInExampleTest` runs it and asserts both.
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
$result = app(AuthorizationRequestService::class)->start(
    application: 'web',
    purpose: Purpose::REAUTHENTICATE,
    connectionId: $connectionId,
    client: $client,
    codeChallenge: $codeChallenge,
    identity: $identity,
    sessionId: $sessionId,
);
// @snippet-end oidc-start-reauthenticate
return $result;
