<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use Tests\Integration\Examples\Routes\Application\Caller;

/**
 * The example application's start routes (SSO-5.1, SSO-12.5): one endpoint per
 * purpose, each fixing its purpose server side. A `sign_in` is public and names
 * a connection or an email address to discover one by; a `link` and a
 * `reauthenticate` are the authenticated caller's own, their identity and
 * session taken from the authentication, never from the body.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoStartController
{
    /**
     * Start flows through the package's helpers.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\AuthorizationRequestService  $requests
     * @param  \SineMacula\Laravel\Sso\Discovery\DiscoveryService  $discovery
     */
    public function __construct(

        /** Starts a flow through a named connection. */
        private AuthorizationRequestService $requests,

        /** Starts a flow through the connection an email's domain is verified for. */
        private DiscoveryService $discovery,
    ) {}

    /**
     * `POST /auth/sso/authorization-requests`: start a sign-in.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function signIn(Request $request): JsonResponse
    {
        // @snippet-start route-start-sign-in
        /** @var array{application: string, connection?: string, email?: string, code_challenge?: ?string} $input */
        $input = Validator::validate($request->all(), [
            'application'    => ['required', 'string'],
            'connection'     => ['required_without:email', 'string'],
            'email'          => ['required_without:connection', 'string', 'max:320'],
            'code_challenge' => ['nullable', 'string'],
        ]);

        $challenge = $input['code_challenge'] ?? null;

        // The purpose is this endpoint's: a `purpose` in the body is never read
        $result = isset($input['email'])
            ? $this->discovery->start($input['application'], Purpose::SIGN_IN, $input['email'], ClientContext::fromRequest($request), $challenge)
            : $this->requests->start($input['application'], Purpose::SIGN_IN, $input['connection'] ?? '', ClientContext::fromRequest($request), $challenge);
        // @snippet-end route-start-sign-in
        return self::answer($result);
    }

    /**
     * `POST /auth/sso/links/authorization-requests`: start linking the caller's
     * identity.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Illuminate\Validation\ValidationException
     */
    public function link(Request $request): JsonResponse
    {
        // @snippet-start route-start-link
        $input = self::input($request);

        $result = $this->requests->start(
            $input['application'],
            Purpose::LINK,
            $input['connection'],
            ClientContext::fromRequest($request),
            $input['code_challenge'] ?? null,
            Caller::identity($request),
        );
        // @snippet-end route-start-link
        return self::answer($result);
    }

    /**
     * `POST /auth/sso/reauthentications/authorization-requests`: start
     * re-authenticating the caller's session.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Illuminate\Validation\ValidationException
     */
    public function reauthenticate(Request $request): JsonResponse
    {
        // @snippet-start route-start-reauthenticate
        $input = self::input($request);

        $result = $this->requests->start(
            $input['application'],
            Purpose::REAUTHENTICATE,
            $input['connection'],
            ClientContext::fromRequest($request),
            $input['code_challenge'] ?? null,
            Caller::identity($request),
            Caller::sessionId($request),
        );
        // @snippet-end route-start-reauthenticate
        return self::answer($result);
    }

    /**
     * The application, the connection and the challenge a start names.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array{application: string, connection: string, code_challenge?: ?string}
     */
    private static function input(Request $request): array
    {
        /** @var array{application: string, connection: string, code_challenge?: ?string} */
        return Validator::validate($request->all(), [
            'application'    => ['required', 'string'],
            'connection'     => ['required', 'string'],
            'code_challenge' => ['nullable', 'string'],
        ]);
    }

    /**
     * The response for a start: its body and headers, which carry
     * `Cache-Control: no-store` and, when rate limited, `Retry-After`.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $result
     * @return \Illuminate\Http\JsonResponse
     */
    private static function answer(StartResult $result): JsonResponse
    {
        // @snippet-start route-start-answer
        $status = match (true) {
            $result->isStarted()     => 200,
            $result->isRateLimited() => 429,
            default                  => 400,
        };

        return response()->json($result->body(), $status, $result->headers());
        // @snippet-end route-start-answer
    }
}
