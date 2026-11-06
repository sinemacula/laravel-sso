<?php

declare(strict_types = 1);

/*
 * The discovery route of `docs/guides/discovery.md` (SSO-3.4, SSO-12.5), as an
 * application's routes file holds it: a start by email address, answered with
 * the start's body and headers, `200` for a match and a miss alike, `429` when
 * rate limited, and `400` for any other refusal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

// @snippet-start discovery-route
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Http\ClientContext;

Route::post('/auth/sso/discovery', static function (Request $request, DiscoveryService $discovery): JsonResponse {
    $result = $discovery->start(
        application: $request->string('application')->toString(),
        purpose: Purpose::SIGN_IN,
        email: $request->string('email')->toString(),
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
// @snippet-end discovery-route
