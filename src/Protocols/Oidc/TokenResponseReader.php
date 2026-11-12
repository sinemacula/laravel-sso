<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\StrictJson;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;

/**
 * Reads a token endpoint's response to an authorisation code; only the ID
 * token, access token and token type are read, and the body is never logged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TokenResponseReader
{
    /** @var list<int> The statuses of an OAuth error response (RFC 6749 section 5.2). */
    private const array ERROR_STATUSES = [400, 401];

    /** @var string The only accepted token type, in lower case. */
    private const string BEARER = 'bearer';

    /**
     * Why the answer is refused, or `null` when it holds tokens. A non-`2xx`
     * answer other than an OAuth error is `fetch_failed`.
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
     * The `error` code of an OAuth error response, for the log only, or `null`.
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
     * The tokens of an answer `refusal()` accepts.
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
     * Why the members of a `2xx` body are refused, or `null`.
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
     * Whether the value is a non-empty string; validation reads the rest.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isIdToken(#[\SensitiveParameter] mixed $value): bool
    {
        return is_string($value) && $value !== '';
    }

    /**
     * Whether the value is an RFC 6750 b64token, by the UserInfo rule.
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
