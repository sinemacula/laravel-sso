<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;

/**
 * Completes an OpenID Connect callback against the request the pipeline
 * consumed for it (SSO-5.4, SSO-7.1, SSO-7.2): the response's `iss` and its
 * code or error, the token request, then the ID token's validation
 * (`IdTokenValidator`) and the claims (`ClaimsAssembler`).
 *
 * In this order, each refusal a value that leaves the request consumed:
 *
 * 1. the raw query is read again by `CallbackParameters`; a refusal now is
 *    `response_invalid`, though the correlator has read it once;
 * 2. RFC 9207: an `iss` present must equal the issuer the request pinned, byte
 *    for byte, and one absent is refused when the request says the provider
 *    returns it; either is `issuer_mismatch`, before the response is handled as
 *    a success or an error. Without `iss`, a response is accepted only at the
 *    callback of the request's own connection, which the consumption has
 *    checked (`connection_mismatch`): the mix-up defence of RFC 9700 §4.4.2;
 * 3. `error` and `code` both present, neither present, or an empty `code` is
 *    `response_invalid`; `error` alone is `provider_error`;
 * 4. the token request (`TokenExchange`, one attempt), with no credential being
 *    `connection_unavailable`, and its answer (`TokenResponseReader`);
 * 5. the ID token's validation, and the claims assembled from it; the verified
 *    completion carries the `Protocols\TransitionReceipt` of a key rotation the
 *    token's own refetch made, which only the validation of the whole token
 *    under the keys it left, and UserInfo when fetched, hands on.
 *
 * The code alone of a provider's error is logged, through the sanitising
 * logger, under `sso.oidc.callback_error` or `sso.oidc.token_error` and only
 * when it has the shape of a code, so prose put in `error` is not logged
 * either; an `error_description` and `error_uri` are never read, so they reach
 * no log, event or result (SSO-5.7). The tokens are never logged or kept
 * (SSO-7.6).
 *
 * The completion runs outside any transaction (`CompletionService`), so the
 * token request never holds a lock. The pipeline refuses under its lock a
 * connection or a trust version changed meanwhile. A database error and a
 * ciphertext no key decrypts propagate (SSO-11.4). It holds nothing between
 * calls (SSO-11.2).
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

    /** @var string The shape of an OAuth error code; anything else is not logged. */
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
     * Complete the callback, or refuse it.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function complete(SsoConnection $connection, OidcOptions $options, CompletionRequest $request, ConsumedRequest $consumed): Completion
    {
        $parameters = CallbackParameters::parse($request->query(), $this->limits);

        if ($parameters === null) {
            return Completion::refused(FailureReason::RESPONSE_INVALID);
        }

        $reason = self::issuerRefusal($parameters, $consumed) ?? $this->responseRefusal($connection, $parameters, $consumed);

        return $reason === null ? $this->exchanged($connection, $options, (string) $parameters->code(), $consumed) : Completion::refused($reason);
    }

    /**
     * Why the response's `iss` refuses it (RFC 9207), or `null`: one present
     * must be the request's pinned issuer, byte for byte, and one absent is
     * accepted only when the request does not require it.
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
     * Why the response's `error` and `code` refuse it, or `null` when it holds
     * exactly a code; an `error` alone is logged by its code.
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
     * Exchange the code, once, and judge what came back.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  string  $code
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function exchanged(SsoConnection $connection, OidcOptions $options, #[\SensitiveParameter] string $code, ConsumedRequest $consumed): Completion
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

        return $this->verified($connection, $options, $this->reader->tokens($fetched), $consumed);
    }

    /**
     * Refuse the token endpoint's answer, logging the code of a provider's
     * error.
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
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function verified(SsoConnection $connection, OidcOptions $options, TokenResponse $tokens, ConsumedRequest $consumed): Completion
    {
        $validation = $this->validator->validate($connection, $options, $tokens, $consumed);

        if (!$validation->isValidated()) {
            return Completion::refused($validation->reason);
        }

        return $this->claims->assemble($connection, $options, $validation->token, $tokens, $consumed)->withReceipt($validation->receipt);
    }

    /**
     * Log a provider's error by its code alone, naming the request by its
     * public reference.
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
