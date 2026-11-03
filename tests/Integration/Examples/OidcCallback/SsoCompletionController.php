<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OidcCallback;

use Illuminate\Http\Request;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponse;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;

/**
 * The controller of `docs/guides/oidc-callback.md` (SSO-5.6, SSO-7.1,
 * SSO-12.5): the OIDC callback, completing the flow the authorisation response
 * answers, from the raw query `CompletionRequest::fromRequest()` keeps, and
 * returning the redirect or refusal `CompletionResponses` builds for its
 * result.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoCompletionController
{
    /**
     * Take the completion helper and the response builder.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionService  $completions
     * @param  \SineMacula\Laravel\Sso\Responses\CompletionResponses  $responses
     */
    public function __construct(

        /** Checks the provider's response and issues the handoff. */
        private CompletionService $completions,

        /** Turns how a completion ended into its redirect or refusal. */
        private CompletionResponses $responses,
    ) {}

    // @snippet-start oidc-callback-action
    /**
     * GET: the OIDC authorisation response the provider sends the browser back
     * with.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \SineMacula\Laravel\Sso\Responses\CompletionResponse
     */
    public function callback(Request $request, string $connection): CompletionResponse
    {
        $result = $this->completions->callback($connection, CompletionRequest::fromRequest($request));

        return $this->responses->from($result, $request->getMethod());
    }
    // @snippet-end oidc-callback-action
}
