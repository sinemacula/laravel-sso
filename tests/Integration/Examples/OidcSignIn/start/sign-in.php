<?php

declare(strict_types = 1);

/*
 * The application's public `sign_in` start endpoint.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

/** @var array{connection: string, code_challenge: ?string, client: \SineMacula\Laravel\Sso\Http\ClientContext} $input */
$connectionId  = $input['connection'];
$codeChallenge = $input['code_challenge'];
$client        = $input['client'];

// @snippet-start oidc-start-sign-in
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;

$result = app(AuthorizationRequestService::class)->start(
    application: 'web',
    purpose: Purpose::SIGN_IN,
    connectionId: $connectionId,
    client: $client,
    codeChallenge: $codeChallenge,
);

$status = match (true) {
    $result->isStarted()     => 200,
    $result->isRateLimited() => 429,
    default                  => 400,
};

return response()->json($result->body(), $status, $result->headers());
// @snippet-end oidc-start-sign-in
