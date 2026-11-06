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
use Tests\Integration\Examples\Routes\Application\SignIns;

/**
 * The example application's sign-in route (SSO-9.2, SSO-9.9, SSO-12.5): it
 * redeems only `sign_in` codes, admits them inside its own transaction on the
 * package's storage connection, writes the session, active or pending, in that
 * transaction, and lets a credential leave only after it commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoSessionController
{
    /**
     * Redeem sign-in codes and write the sessions they establish.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffRedemption  $redemptions
     * @param  \Tests\Integration\Examples\Routes\Application\SignIns  $signIns
     */
    public function __construct(

        /** Redeems handoff codes. */
        private HandoffRedemption $redemptions,

        /** The application's own sessions and credentials. */
        private SignIns $signIns,
    ) {}

    /**
     * `POST /auth/sessions`: redeem a sign-in handoff.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Validation\ValidationException
     * @throws \Throwable
     */
    public function store(Request $request): JsonResponse
    {
        // @snippet-start route-sign-in
        /** @var array{application: string, connection: string, code: string, verifier: string} $input */
        $input = Validator::validate($request->all(), [
            'application' => ['required', 'string'],
            'connection'  => ['required', 'string'],
            'code'        => ['required', 'string'],
            'verifier'    => ['required', 'string'],
        ]);

        $client = ClientContext::fromRequest($request);

        // The code is consumed and the session written in one transaction, on
        // the package's storage connection
        [$result, $sessionId] = DB::connection(StorageConnection::name())->transaction(function () use ($input, $client): array {
            $result = $this->redemptions->admit(Purpose::SIGN_IN, $input['application'], $input['connection'], $input['code'], $input['verifier'], $client);

            // Active, or pending your own further factor; an unlinked handoff
            // signs nobody in
            $sessionId = $result->isRedeemed() && $result->linkedIdentity !== null ? $this->signIns->start($result) : null;

            return [$result, $sessionId];
        });

        // Only now, after the commit, does a credential leave
        return $sessionId === null
            ? self::refusal($result)
            : response()->json($this->signIns->credential($sessionId), 200, Answers::NO_STORE);
        // @snippet-end route-sign-in
    }

    /**
     * The refusal of a redemption that admitted no identity: a full limit, a
     * refused code, or an unlinked handoff the application does not sign in.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $result
     * @return \Illuminate\Http\JsonResponse
     */
    private static function refusal(RedemptionResult $result): JsonResponse
    {
        // @snippet-start route-sign-in-refusal
        return $result->isRateLimited() ? Answers::rateLimited($result->retryAfter) : Answers::refused($result->reason ?? FailureReason::UNLINKED);
        // @snippet-end route-sign-in-refusal
    }
}
