<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Responses;

use SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionStatus;
use SineMacula\Laravel\Sso\Localization\Enums\Message;
use SineMacula\Laravel\Sso\Localization\Messages;

/**
 * Turns a completion result into the response the controller returns.
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
     * The response to the completion result, which arrived by the method given.
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
     * The redirect URI with the parameter and reference appended in the
     * fragment or query.
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
     * The completed result's handoff code, revealed for its redirect.
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
     * The failed result's reason code.
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
     * The re-initiated result's start URL.
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
     * The seconds a rate-limited result waits.
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
