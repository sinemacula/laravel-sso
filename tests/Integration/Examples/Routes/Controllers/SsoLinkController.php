<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Links\LinkService;
use Tests\Integration\Examples\Routes\Application\Answers;
use Tests\Integration\Examples\Routes\Application\Caller;

/**
 * The example application's link routes (SSO-5.11, SSO-8.3, SSO-12.5): the
 * authenticated caller redeems a `link` code for themselves, lists their links
 * and removes one of their own. The caller is always the authentication's,
 * never the body's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoLinkController
{
    /**
     * Redeem, list and remove links through the package's helpers.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffRedemption  $redemptions
     * @param  \SineMacula\Laravel\Sso\Links\LinkService  $links
     */
    public function __construct(

        /** Redeems handoff codes. */
        private HandoffRedemption $redemptions,

        /** Lists and removes an identity's links. */
        private LinkService $links,
    ) {}

    /**
     * `POST /auth/sso/links`: redeem a link handoff for the caller.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): JsonResponse
    {
        // @snippet-start route-link
        /** @var array{application: string, connection: string, code: string, verifier: string} $input */
        $input = Validator::validate($request->all(), [
            'application' => ['required', 'string'],
            'connection'  => ['required', 'string'],
            'code'        => ['required', 'string'],
            'verifier'    => ['required', 'string'],
        ]);

        // A `link` writes no session, so it is redeemed alone, for the caller
        // the application authenticated
        $result = $this->redemptions->redeem(
            Purpose::LINK,
            $input['application'],
            $input['connection'],
            $input['code'],
            $input['verifier'],
            ClientContext::fromRequest($request),
            Caller::identity($request),
        );

        return match (true) {
            $result->isRedeemed()    => response()->json(['link' => $result->linkId], 201, Answers::NO_STORE),
            $result->isRateLimited() => Answers::rateLimited($result->retryAfter),
            default                  => Answers::refused($result->reason ?? FailureReason::HANDOFF_UNKNOWN),
        };
        // @snippet-end route-link
    }

    /**
     * `GET /auth/sso/links`: the caller's links.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function index(Request $request): JsonResponse
    {
        // @snippet-start route-links
        return response()->json($this->links->list('me', Caller::identity($request)), 200, Answers::NO_STORE);
        // @snippet-end route-links
    }

    /**
     * `DELETE /auth/sso/links/{link}`: remove one of the caller's links.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $link
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function destroy(Request $request, string $link): JsonResponse
    {
        // @snippet-start route-link-remove
        $result = $this->links->remove('me', $link, ClientContext::fromRequest($request), Caller::identity($request), Caller::actor($request));

        return Answers::of($result, 200);
        // @snippet-end route-link-remove
    }
}
