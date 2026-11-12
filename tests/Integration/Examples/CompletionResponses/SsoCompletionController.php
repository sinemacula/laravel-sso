<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\CompletionResponses;

use Illuminate\Http\Request;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponse;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;

/**
 * The completion controller of `docs/guides/completion-responses.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoCompletionController
{
    // @snippet-start response-controller
    /**
     * Take the completion helper and the response builder.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionService  $completions
     * @param  \SineMacula\Laravel\Sso\Responses\CompletionResponses  $responses
     */
    public function __construct(

        /** Checks the identity provider's response and issues the handoff. */
        private CompletionService $completions,

        /** Turns how a completion ended into its redirect or refusal. */
        private CompletionResponses $responses,
    ) {}

    /**
     * POST: the SAML response, posted by the browser.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \SineMacula\Laravel\Sso\Responses\CompletionResponse
     */
    public function assertion(Request $request, string $connection): CompletionResponse
    {
        $result = $this->completions->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $connection,
            CompletionRequest::fromRequest($request),
            ClientContext::fromRequest($request),
        );

        return $this->responses->from($result, $request->getMethod());
    }

    /**
     * GET: the OIDC authorisation response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \SineMacula\Laravel\Sso\Responses\CompletionResponse
     */
    public function callback(Request $request, string $connection): CompletionResponse
    {
        $result = $this->completions->complete(
            CompletionEndpoint::CALLBACK,
            $connection,
            CompletionRequest::fromRequest($request),
            ClientContext::fromRequest($request),
        );

        return $this->responses->from($result, $request->getMethod());
    }
    // @snippet-end response-controller
}
