<?php

declare(strict_types = 1);

/*
 * The sign-in start route of `docs/guides/rate-limits.md` (SSO-11.8, SSO-12.5),
 * as an application's routes file holds it: a start through the connection the
 * client names, answered `429` with the seconds to wait in `Retry-After` when
 * the client's IP address has used its starts, and otherwise with the start's
 * body and headers, `200` when the client is sent on to the provider and `400`
 * for any other refusal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;

Route::post('/auth/sso/start', static function (Request $request, AuthorizationRequestService $flows): JsonResponse {
    $result = $flows->start('web', Purpose::SIGN_IN, $request->string('connection')->toString());

    // @snippet-start rate-limited-answer
    if ($result->isRateLimited()) {
        return response()->json(['error' => 'rate_limited'], 429, [
            'Retry-After' => (string) $result->retryAfter,
        ]);
    }
    // @snippet-end rate-limited-answer
    return response()->json($result->body(), $result->isStarted() ? 200 : 400, $result->headers());
});
