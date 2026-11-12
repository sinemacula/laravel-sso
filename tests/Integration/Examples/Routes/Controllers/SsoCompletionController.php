<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Controllers;

use Illuminate\Http\Request;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponse;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;

/**
 * The example application's SAML assertion consumer service and OIDC callback.
 * They take no session or authentication; the completion checks the response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoCompletionController
{
    /**
     * Complete flows through the package's helpers.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionService  $completions
     * @param  \SineMacula\Laravel\Sso\Responses\CompletionResponses  $responses
     */
    public function __construct(

        /** Validates the identity provider's response and issues the handoff. */
        private CompletionService $completions,

        /** Turns a completion's result into its redirect or refusal. */
        private CompletionResponses $responses,
    ) {}

    /**
     * `POST /auth/sso/connections/{connection}/assertions`: the SAML response,
     * posted by the browser.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \SineMacula\Laravel\Sso\Responses\CompletionResponse
     */
    public function assertion(Request $request, string $connection): CompletionResponse
    {
        // @snippet-start route-assertion
        $result = $this->completions->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $connection,
            CompletionRequest::fromRequest($request),
            ClientContext::fromRequest($request),
        );

        return $this->responses->from($result, $request->getMethod());
        // @snippet-end route-assertion
    }

    /**
     * `GET /auth/sso/connections/{connection}/callback`: the OIDC authorisation
     * response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \SineMacula\Laravel\Sso\Responses\CompletionResponse
     */
    public function callback(Request $request, string $connection): CompletionResponse
    {
        // @snippet-start route-callback
        $result = $this->completions->complete(
            CompletionEndpoint::CALLBACK,
            $connection,
            CompletionRequest::fromRequest($request),
            ClientContext::fromRequest($request),
        );

        return $this->responses->from($result, $request->getMethod());
        // @snippet-end route-callback
    }
}
