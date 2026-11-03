<?php

declare(strict_types = 1);

/*
 * The sign-in start of `docs/guides/oidc-sign-in.md` (SSO-5.1, SSO-5.4,
 * SSO-12.5), as the application's public start endpoint runs it, given the
 * connection the client names and the PKCE challenge it sends, if any: the
 * package starts an OIDC `sign_in` through the connection, and the endpoint
 * answers with the start's body and headers, `200` when the client is sent on
 * to the provider, `429` when rate limited and `400` for any other refusal.
 * `OidcSignInExampleTest` runs it and asserts the answer, what the provider is
 * sent, and a refusal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

/** @var array{connection: string, code_challenge: ?string} $input */
$connectionId  = $input['connection'];
$codeChallenge = $input['code_challenge'];

// @snippet-start oidc-start-sign-in
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;

$result = app(AuthorizationRequestService::class)->start(
    application: 'web',
    purpose: Purpose::SIGN_IN,
    connectionId: $connectionId,
    codeChallenge: $codeChallenge,
);

$status = match (true) {
    $result->isStarted()     => 200,
    $result->isRateLimited() => 429,
    default                  => 400,
};

return response()->json($result->body(), $status, $result->headers());
// @snippet-end oidc-start-sign-in
