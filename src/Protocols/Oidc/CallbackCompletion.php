<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;

/**
 * Completes an OpenID Connect callback: checks `iss` and the code or error,
 * exchanges the code, then validates the ID token and assembles the claims.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallbackCompletion
{
    /** @var string The log message of an `error` the authorisation response carried. */
    private const string CALLBACK_ERROR = 'sso.oidc.callback_error';

    /** @var string The log message of an `error` the token endpoint answered. */
    private const string TOKEN_ERROR = 'sso.oidc.token_error';

    /** @var string The shape of an OAuth error code; prose in `error` is not logged. */
    private const string ERROR_CODE = '/^[A-Za-z0-9_.:\-]{1,64}$/D';

    /** @var string What is logged for an `error` that is not shaped as a code. */
    private const string UNRECOGNIZED_ERROR = '[unrecognized]';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits  $limits
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\TokenExchange  $exchange
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\TokenResponseReader  $reader
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator  $validator
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\ClaimsAssembler  $claims
     * @param  \Psr\Log\LoggerInterface  $logger
     */
    public function __construct(

        /** The caps on the callback's parameters. */
        private OidcLimits $limits,

        /** Sends the token request. */
        private TokenExchange $exchange,

        /** Reads what the token endpoint answered. */
        private TokenResponseReader $reader,

        /** Validates the ID token. */
        private IdTokenValidator $validator,

        /** Builds the verified claims. */
        private ClaimsAssembler $claims,

        /** The sanitising logger. */
        private LoggerInterface $logger,
    ) {}

    /**
     * Complete the callback, or refuse it; every refusal leaves the request
     * consumed.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function complete(SsoConnection $connection, OidcOptions $options, CompletionRequest $request, ConsumedRequest $consumed, ClientContext $client): Completion
    {
        $parameters = CallbackParameters::parse($request->query(), $this->limits);

        if ($parameters === null) {
            return Completion::refused(FailureReason::RESPONSE_INVALID);
        }

        $reason = self::issuerRefusal($parameters, $consumed) ?? $this->responseRefusal($connection, $parameters, $consumed);

        return $reason === null ? $this->exchanged($connection, $options, (string) $parameters->code(), $consumed, $client) : Completion::refused($reason);
    }

    /**
     * Why the response's RFC 9207 `iss` refuses it, or `null`. Checked before
     * the response is read as a success or an error.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\CallbackParameters  $parameters
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function issuerRefusal(CallbackParameters $parameters, ConsumedRequest $consumed): ?FailureReason
    {
        $iss      = $parameters->iss();
        $accepted = $iss === null ? !$consumed->issuerRequired : $iss === $consumed->expectedIssuer;

        return $accepted ? null : FailureReason::ISSUER_MISMATCH;
    }

    /**
     * Why the `error` and `code` refuse the response, or `null` when it holds
     * exactly a code.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\CallbackParameters  $parameters
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function responseRefusal(SsoConnection $connection, CallbackParameters $parameters, ConsumedRequest $consumed): ?FailureReason
    {
        $error = $parameters->error();
        $code  = $parameters->code();

        if ($error !== null && $code === null) {
            $this->logError(self::CALLBACK_ERROR, $connection, $consumed, $error);

            return FailureReason::PROVIDER_ERROR;
        }

        $codeAlone = $error === null && $code !== null;

        return $codeAlone && $code !== '' ? null : FailureReason::RESPONSE_INVALID;
    }

    /**
     * Exchange the code once and judge the answer.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  string  $code
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function exchanged(SsoConnection $connection, OidcOptions $options, #[\SensitiveParameter] string $code, ConsumedRequest $consumed, ClientContext $client): Completion
    {
        $credentials = $this->exchange->credentials($connection, $options);

        if ($credentials === null) {
            return Completion::refused(FailureReason::CONNECTION_UNAVAILABLE);
        }

        $fetched = $this->exchange->send($connection, $options, $code, $consumed, $credentials);
        $reason  = $this->reader->refusal($fetched);

        if ($reason !== null) {
            return $this->refusedAnswer($connection, $consumed, $fetched, $reason);
        }

        return $this->verified($connection, $options, $this->reader->tokens($fetched), $consumed, $client);
    }

    /**
     * Refuse the token endpoint's answer, logging any provider error code.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $fetched
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function refusedAnswer(SsoConnection $connection, ConsumedRequest $consumed, FetchResult $fetched, FailureReason $reason): Completion
    {
        $error = $this->reader->providerError($fetched);

        if ($error !== null) {
            $this->logError(self::TOKEN_ERROR, $connection, $consumed, $error);
        }

        return Completion::refused($reason);
    }

    /**
     * Validate the ID token and assemble the claims from it.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse  $tokens
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function verified(SsoConnection $connection, OidcOptions $options, TokenResponse $tokens, ConsumedRequest $consumed, ClientContext $client): Completion
    {
        $validation = $this->validator->validate($connection, $options, $tokens, $consumed, $client);

        if (!$validation->isValidated()) {
            return Completion::refused($validation->reason);
        }

        return $this->claims->assemble($connection, $options, $validation->token, $tokens, $consumed)->withReceipt($validation->receipt);
    }

    /**
     * Log a provider's error code alone, with the request's public reference.
     *
     * @param  string  $message
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  string  $error
     * @return void
     */
    private function logError(string $message, SsoConnection $connection, ConsumedRequest $consumed, #[\SensitiveParameter] string $error): void
    {
        $this->logger->notice($message, [
            'connection_id'     => $connection->getConnectionId(),
            'request_reference' => $consumed->reference->value,
            'error'             => preg_match(self::ERROR_CODE, $error) === 1 ? $error : self::UNRECOGNIZED_ERROR,
        ]);
    }
}
