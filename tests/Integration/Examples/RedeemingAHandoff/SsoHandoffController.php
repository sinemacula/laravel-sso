<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RedeemingAHandoff;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;

/**
 * The sign-in redemption endpoint of `docs/guides/redeeming-a-handoff.md`
 * (SSO-9.2, SSO-9.8, SSO-9.9, SSO-12.5): it redeems only `sign_in` codes,
 * admits each inside its own transaction on the package's storage connection,
 * writes the session there, and answers every outcome with `Cache-Control:
 * no-store`, the token leaving only after the commit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoHandoffController
{
    /**
     * Redeem sign-in codes and write the sessions they establish.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffRedemption  $redemptions
     * @param  \Tests\Integration\Examples\RedeemingAHandoff\SignIns  $signIns
     */
    public function __construct(

        /** Redeems handoff codes. */
        private HandoffRedemption $redemptions,

        /** The application's own sessions and tokens. */
        private SignIns $signIns,
    ) {}

    // @snippet-start handoff-controller
    /**
     * `POST /api/auth/sessions`: redeem a sign-in handoff.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    public function signIn(Request $request): JsonResponse
    {
        [$result, $sessionId] = DB::connection(StorageConnection::name())->transaction(function () use ($request): array {
            $result = $this->redemptions->admit(
                Purpose::SIGN_IN,
                'web',                                    // your application's name, as configured
                $request->string('connection')->value(),  // the connection the client started through
                $request->string('code')->value(),
                $request->string('verifier')->value(),
            );

            // Sign in the identity the code's link resolved to, in this same
            // transaction; an unlinked handoff names none
            $sessionId = $result->isAdmitted() && $result->linkedIdentity !== null
                ? $this->signIns->start($result->linkedIdentity, (string) $result->linkId)
                : null;

            return [$result, $sessionId];
        });

        if ($result->isRateLimited()) {
            return response()->json(['error' => 'rate_limited'], 429, [
                'Retry-After'   => (string) $result->retryAfter,
                'Cache-Control' => 'no-store',
            ]);
        }

        if ($sessionId === null) {
            return response()->json(['error' => ($result->reason ?? FailureReason::UNLINKED)->value], 400, ['Cache-Control' => 'no-store']);
        }

        // Only now, after the commit, does your token leave
        return response()->json(['token' => $this->signIns->token($sessionId)], 200, ['Cache-Control' => 'no-store']);
    }
    // @snippet-end handoff-controller
}
