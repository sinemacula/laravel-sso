<?php

declare(strict_types = 1);

/*
 * The start route of `docs/guides/starting-a-flow.md`.
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
use SineMacula\Laravel\Sso\Http\ClientContext;

Route::post('/auth/sso/authorization-requests', static function (Request $request, AuthorizationRequestService $requests): JsonResponse {
    $result = $requests->start(
        application: $request->string('application')->toString(),
        purpose: Purpose::SIGN_IN,
        connectionId: $request->string('connection')->toString(),
        client: ClientContext::fromRequest($request),
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
