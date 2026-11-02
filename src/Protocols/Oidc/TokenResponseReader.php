<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\StrictJson;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;

/**
 * Reads what a token endpoint answered an authorisation code with (SSO-7.2,
 * SSO-7.6).
 *
 * `refusal()` says why the answer is refused, or `null` when it holds tokens:
 *
 * - a request refused or failed is `fetch_refused` or `fetch_failed`, a timeout
 *   and a body over the request's cap among them;
 * - a `400` or `401` whose body is a JSON object with a string `error` is
 *   `provider_error`, whose code alone `providerError()` answers for the log;
 * - any other status outside `2xx`, `3xx` and `5xx` among them, is
 *   `fetch_failed`, since a credentialed request follows no redirect and is
 *   never retried;
 * - a `2xx` body must be a JSON object read by `Jose\StrictJson`, so a repeated
 *   member is refused, else `token_response_invalid`; its `id_token` a
 *   non-empty string, else `id_token_invalid`; its `access_token` an RFC 6750
 *   b64token (`FetchCredentials::accessToken()`'s rule) and its `token_type`
 *   `Bearer` in any case, else `token_response_invalid`. Each is read as JSON
 *   wrote it, so a number is never taken for a string of its digits.
 *
 * `tokens()` builds the `Tokens\TokenResponse` of an answer not refused.
 * Nothing else of the body is read or kept, a refresh token and
 * `error_description` above all; the body is never logged. It holds nothing
 * between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TokenResponseReader
{
    /** @var list<int> The statuses of an OAuth error response (RFC 6749 §5.2). */
    private const array ERROR_STATUSES = [400, 401];

    /** @var string The one token type the package accepts, in lower case. */
    private const string BEARER = 'bearer';

    /**
     * Why the answer is refused, or `null` when it holds tokens.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $result
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public function refusal(FetchResult $result): ?FailureReason
    {
        if (!$result->isFetched()) {
            return $result->reason ?? FailureReason::FETCH_FAILED;
        }

        if ($result->isSuccessful()) {
            return self::memberRefusal(StrictJson::decodeMembers((string) $result->body()));
        }

        return $this->providerError($result) === null ? FailureReason::FETCH_FAILED : FailureReason::PROVIDER_ERROR;
    }

    /**
     * The `error` of an OAuth error response, for the log alone, or `null` when
     * the answer is not one.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $result
     * @return ?string
     */
    public function providerError(FetchResult $result): ?string
    {
        if (!in_array($result->statusCode, self::ERROR_STATUSES, true)) {
            return null;
        }

        $error = StrictJson::decodeMembers((string) $result->body())['error'] ?? null;

        return is_string($error) && $error !== '' ? $error : null;
    }

    /**
     * The tokens of an answer `refusal()` does not refuse; any other is the
     * caller's mistake.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $result
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse
     *
     * @throws \LogicException
     */
    public function tokens(FetchResult $result): TokenResponse
    {
        if ($this->refusal($result) !== null) {
            throw new \LogicException('Only an answer that is not refused holds tokens.');
        }

        /** @var array{id_token: string, access_token: string, token_type: string} $members */
        $members = StrictJson::decodeMembers((string) $result->body());

        return new TokenResponse($members['id_token'], $members['access_token'], $members['token_type']);
    }

    /**
     * Why the members of a `2xx` body are refused, or `null` when they hold the
     * tokens.
     *
     * @param  ?array<array-key, mixed>  $members
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function memberRefusal(#[\SensitiveParameter] ?array $members): ?FailureReason
    {
        return match (true) {
            $members === null                                   => FailureReason::TOKEN_RESPONSE_INVALID,
            !self::isIdToken($members['id_token'] ?? null)      => FailureReason::ID_TOKEN_INVALID,
            !self::isB64Token($members['access_token'] ?? null) => FailureReason::TOKEN_RESPONSE_INVALID,
            !self::isBearer($members['token_type'] ?? null)     => FailureReason::TOKEN_RESPONSE_INVALID,
            default                                             => null,
        };
    }

    /**
     * Whether the value is a non-empty string; the ID token's validation reads
     * the rest of it.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isIdToken(#[\SensitiveParameter] mixed $value): bool
    {
        return is_string($value) && $value !== '';
    }

    /**
     * Whether the value is what a bearer token may hold, by the rule the
     * UserInfo request sends it under.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isB64Token(#[\SensitiveParameter] mixed $value): bool
    {
        if (!is_string($value)) {
            return false;
        }

        try {
            FetchCredentials::accessToken($value);
        } catch (\InvalidArgumentException) {
            return false;
        }

        return true;
    }

    /**
     * Whether the value names the bearer token type, in any case.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isBearer(mixed $value): bool
    {
        return is_string($value) && strtolower($value) === self::BEARER;
    }
}
