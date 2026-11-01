<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Responses;

use SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionStatus;
use SineMacula\Laravel\Sso\Localization\Enums\Message;
use SineMacula\Laravel\Sso\Localization\Messages;

/**
 * Turns how a completion ended into the response the application's controller
 * returns (SSO-5.6, SSO-5.7, SSO-12.1):
 *
 * - `completed`: a redirect to the application's redirect URI with `code` and
 *   `reference`, in the fragment or the query as the application delivers;
 * - `failed`: a redirect to the same URI with `error`, the failure reason's
 *   code, and `reference`, never a reason in prose, the identity provider's
 *   error description or an assertion;
 * - `reinitiated`: a redirect to the connection's start URL, exactly as given;
 * - `rejected`: a `400` with no redirect, since no trusted target is known;
 * - `rate_limited`: a `429` with `Retry-After` and no redirect.
 *
 * A redirect is a `303` after a POST and a `302` after a GET, and a `303` after
 * any other method; never a `307` or a `308`. The body of a redirect and of a
 * refusal is a message read through Laravel's translator in the current locale
 * (SSO-12.6), the same whatever the reason.
 *
 * It catches nothing: a database error never becomes a completion result, since
 * the completion propagates it as a server error (SSO-11.4), and an error here
 * propagates too, so a failure is never turned into a failure redirect.
 *
 * It keeps only the messages it was given, so nothing of one request or job
 * outlives it (SSO-11.2).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CompletionResponses
{
    /** @var string The method a redirect answers with a `302`; every other one gets a `303`. */
    private const string GET = 'GET';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Localization\Messages  $messages
     */
    public function __construct(

        /** The messages put in front of the person signing in. */
        private Messages $messages,
    ) {}

    /**
     * The response to a completion that ended as the result says, after it
     * arrived by the HTTP method given.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @param  string  $method
     * @return \SineMacula\Laravel\Sso\Responses\CompletionResponse
     *
     * @throws \LogicException
     */
    public function from(CompletionResult $result, string $method): CompletionResponse
    {
        return match ($result->status) {
            CompletionStatus::COMPLETED    => $this->redirect($method, self::onRedirectUri($result, 'code', self::revealedCode($result))),
            CompletionStatus::FAILED       => $this->redirect($method, self::onRedirectUri($result, 'error', self::reasonCode($result))),
            CompletionStatus::REINITIATED  => $this->redirect($method, self::startUrl($result)),
            CompletionStatus::REJECTED     => CompletionResponse::rejected($this->messages->get(Message::COMPLETION_INVALID)),
            CompletionStatus::RATE_LIMITED => CompletionResponse::rateLimited(self::retryAfter($result), $this->messages->get(Message::COMPLETION_INVALID)),
        };
    }

    /**
     * A redirect to the location, with the status the method calls for.
     *
     * @param  string  $method
     * @param  string  $location
     * @return \SineMacula\Laravel\Sso\Responses\CompletionResponse
     *
     * @throws \LogicException
     */
    private function redirect(string $method, #[\SensitiveParameter] string $location): CompletionResponse
    {
        $status = strtoupper($method) === self::GET ? CompletionResponse::FOUND : CompletionResponse::SEE_OTHER;

        return CompletionResponse::redirect($status, $location, $this->messages->get(Message::COMPLETION_REDIRECTING));
    }

    /**
     * The application's redirect URI, otherwise unchanged, with the parameter
     * named and then the reference appended: after `#` in the fragment, or in
     * the query after `?`, or `&` when the URI already has a query.
     *
     * The configured URI never has a fragment, so the fragment is the package's
     * alone.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @param  string  $name
     * @param  string  $value
     * @return string
     */
    private static function onRedirectUri(CompletionResult $result, string $name, #[\SensitiveParameter] string $value): string
    {
        /** @var string $uri */
        $uri = $result->redirectUri;

        /** @var \SineMacula\Laravel\Sso\Flows\RequestReference $reference */
        $reference  = $result->reference;
        $parameters = http_build_query([$name => $value, 'reference' => $reference->value], '', '&', PHP_QUERY_RFC3986);

        if ($result->delivery !== HandoffDelivery::QUERY) {
            return $uri . '#' . $parameters;
        }

        return $uri . (str_contains($uri, '?') ? '&' : '?') . $parameters;
    }

    /**
     * The handoff code of a completed result, revealed for its redirect.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return string
     */
    private static function revealedCode(CompletionResult $result): string
    {
        /** @var \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff $handoff */
        $handoff = $result->handoff;

        return $handoff->code->reveal();
    }

    /**
     * The failure reason's code of a failed result.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return string
     */
    private static function reasonCode(CompletionResult $result): string
    {
        /** @var \SineMacula\Laravel\Sso\Events\Enums\FailureReason $reason */
        $reason = $result->reason;

        return $reason->value;
    }

    /**
     * The connection's start URL of a re-initiated result.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return string
     */
    private static function startUrl(CompletionResult $result): string
    {
        /** @var string */
        return $result->startUrl;
    }

    /**
     * The seconds a rate limited result waits.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return int
     */
    private static function retryAfter(CompletionResult $result): int
    {
        /** @var int */
        return $result->retryAfter;
    }
}
