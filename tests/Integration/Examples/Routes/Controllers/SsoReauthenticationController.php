<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use Tests\Integration\Examples\Routes\Application\Answers;
use Tests\Integration\Examples\Routes\Application\Caller;

/**
 * The example application's re-authentication route.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoReauthenticationController
{
    /**
     * Redeem re-authentication codes.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffRedemption  $redemptions
     */
    public function __construct(

        /** Redeems handoff codes. */
        private HandoffRedemption $redemptions,
    ) {}

    /**
     * `POST /auth/sso/reauthentications`: redeem a re-authentication handoff
     * for the caller's session.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Illuminate\Validation\ValidationException
     * @throws \Throwable
     */
    public function store(Request $request): JsonResponse
    {
        // @snippet-start route-reauthenticate
        /** @var array{application: string, connection: string, code: string, verifier: string} $input */
        $input = Validator::validate($request->all(), [
            'application' => ['required', 'string'],
            'connection'  => ['required', 'string'],
            'code'        => ['required', 'string'],
            'verifier'    => ['required', 'string'],
        ]);

        // The package renews the code's session inside this transaction, once; nothing renews it again
        $result = DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => $this->redemptions->admit(
                Purpose::REAUTHENTICATE,
                $input['application'],
                $input['connection'],
                $input['code'],
                $input['verifier'],
                ClientContext::fromRequest($request),
            ),
        );

        // The code renewed the session it was started on: only when that is the
        // caller's own is the caller fresh
        $renewed = $result->isRedeemed() && $result->sessionId === Caller::sessionId($request);

        return match (true) {
            $renewed                 => response()->json(['status' => 'reauthenticated'], 200, Answers::NO_STORE),
            $result->isRateLimited() => Answers::rateLimited($result->retryAfter),
            default                  => Answers::refused($result->reason ?? FailureReason::SESSION_INELIGIBLE),
        };
        // @snippet-end route-reauthenticate
    }
}
