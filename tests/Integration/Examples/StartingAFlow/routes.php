<?php

declare(strict_types = 1);

/*
 * The start route of `docs/guides/starting-a-flow.md` (SSO-5.1, SSO-5.12,
 * SSO-11.8, SSO-12.5), as an application's routes file holds it: a `sign_in`
 * for the application and through the connection the client names, with the
 * client's challenge when it sends one, answered with the start's body and
 * headers, `200` when the client is sent on to the provider, `429` when its IP
 * address has used its starts and `400` for any other refusal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

// @snippet-start authorization-requests-route
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;

Route::post('/auth/sso/authorization-requests', static function (Request $request, AuthorizationRequestService $requests): JsonResponse {
    $result = $requests->start(
        application: $request->string('application')->toString(),
        purpose: Purpose::SIGN_IN,
        connectionId: $request->string('connection')->toString(),
        codeChallenge: $request->has('code_challenge') ? $request->string('code_challenge')->toString() : null,
    );

    $status = match (true) {
        $result->isStarted()     => 200,
        $result->isRateLimited() => 429,
        default                  => 400,
    };

    return response()->json($result->body(), $status, $result->headers());
});
// @snippet-end authorization-requests-route
