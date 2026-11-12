<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\StrictJson;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken;

/**
 * Sends the UserInfo request of an OpenID Connect completion and reads the
 * response. Once enabled UserInfo is mandatory, so any refusal fails the flow.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UserInfoReader
{
    /** @var list<int> The statuses of a UserInfo error response (RFC 6750 section 3.1). */
    private const array PROVIDER_ERROR_STATUSES = [401, 403];

    /** @var list<string> The only bearer error codes logged (RFC 6750 section 3.1). */
    private const array ERROR_CODES = ['invalid_request', 'invalid_token', 'insufficient_scope'];

    /** @var list<string> The string claims read beside the email. */
    private const array TEXT_CLAIMS = ['name', 'given_name', 'family_name'];

    /** @var string The content type of an unsupported signed or encrypted response. */
    private const string JWT_CONTENT_TYPE = 'application/jwt';

    /** @var string One `WWW-Authenticate` parameter: its name and token or quoted string. */
    private const string CHALLENGE_PARAMETER = '/([!#$%&\'*+.^_`|~0-9A-Za-z-]++)\s*+=\s*+("(?:[^"\\\]++|\\\.)*+"|[^\s,"]*+)/';

    /** @var string The challenge parameter that holds the error code. */
    private const string ERROR_PARAMETER = 'error';

    /** @var string The message for a UserInfo request inside a storage transaction. */
    private const string INSIDE_TRANSACTION = 'A UserInfo request is sent outside any transaction on the package\'s storage connection: a provider call never holds a lock.';

    /** @var string The message for a connection with no UserInfo endpoint. */
    private const string NO_ENDPOINT = 'A connection that fetches UserInfo names its endpoint; only a complete connection is used.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Fetcher  $fetcher
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits  $limits
     */
    public function __construct(

        /** Sends the one attempt. */
        private Fetcher $fetcher,

        /** The request's timeout and size cap. */
        private OidcLimits $limits,
    ) {}

    /**
     * Send the UserInfo request once, with the access token alone.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse  $tokens
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     *
     * @throws \LogicException
     * @throws \InvalidArgumentException
     */
    public function fetch(OidcOptions $options, TokenResponse $tokens): FetchResult
    {
        StorageConnection::assertNoTransaction(self::INSIDE_TRANSACTION);

        return $this->fetcher->fetch(FetchRequest::userInfo(
            self::endpoint($options),
            FetchCredentials::accessToken($tokens->accessToken()),
            $this->limits->userInfoTimeoutSeconds(),
            $this->limits->maxUserInfoBytes(),
        ));
    }

    /**
     * Why the answer is refused, or `null` when its claims may be read.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $result
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken  $idToken
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public function refusal(FetchResult $result, ValidatedIdToken $idToken): ?FailureReason
    {
        return match (true) {
            !$result->isFetched()                                              => $result->reason ?? FailureReason::FETCH_FAILED,
            in_array($result->statusCode, self::PROVIDER_ERROR_STATUSES, true) => FailureReason::PROVIDER_ERROR,
            !$result->isSuccessful()                                           => FailureReason::FETCH_FAILED,
            self::isSignedOrEncrypted($result)                                 => FailureReason::USERINFO_INVALID,
            default                                                            => self::bodyRefusal((string) $result->body(), $idToken->subject()),
        };
    }

    /**
     * The RFC 6750 error code from `WWW-Authenticate`, for the log only, or
     * `null`; `error_description` is never read.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $result
     * @return ?string
     */
    public function providerError(FetchResult $result): ?string
    {
        preg_match_all(self::CHALLENGE_PARAMETER, (string) $result->header('WWW-Authenticate'), $parameters, PREG_SET_ORDER);

        foreach ($parameters as [, $name, $value]) {

            if (strtolower($name) !== self::ERROR_PARAMETER) {
                continue;
            }

            $code = trim($value, '"');

            return in_array($code, self::ERROR_CODES, true) ? $code : null;
        }

        return null;
    }

    /**
     * The claims of an answer `refusal()` accepts.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $result
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken  $idToken
     * @return array<array-key, mixed>
     *
     * @throws \LogicException
     */
    public function claims(FetchResult $result, ValidatedIdToken $idToken): array
    {
        if ($this->refusal($result, $idToken) !== null) {
            throw new \LogicException('Only an answer that is not refused holds claims.');
        }

        /** @var array<array-key, mixed> */
        return StrictJson::decodeMembers((string) $result->body());
    }

    /**
     * The connection's UserInfo endpoint, which a complete connection has.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @return string
     *
     * @throws \LogicException
     */
    private static function endpoint(OidcOptions $options): string
    {
        return $options->userInfoEndpoint() ?? throw new \LogicException(self::NO_ENDPOINT);
    }

    /**
     * Whether the content type is `application/jwt`, ignoring case and
     * parameters.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $result
     * @return bool
     */
    private static function isSignedOrEncrypted(FetchResult $result): bool
    {
        $type = explode(';', (string) $result->header('Content-Type'))[0];

        return strtolower(trim($type)) === self::JWT_CONTENT_TYPE;
    }

    /**
     * Why a `2xx` body is refused, or `null` when its claims may be read.
     *
     * @param  string  $body
     * @param  string  $subject
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function bodyRefusal(#[\SensitiveParameter] string $body, #[\SensitiveParameter] string $subject): ?FailureReason
    {
        $claims = StrictJson::decodeMembers($body);

        return $claims !== null && self::hasFittingClaims($claims, $subject) ? null : FailureReason::USERINFO_INVALID;
    }

    /**
     * Whether `sub` is exactly the subject and the read claims are typed.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  string  $subject
     * @return bool
     */
    private static function hasFittingClaims(#[\SensitiveParameter] array $claims, #[\SensitiveParameter] string $subject): bool
    {
        $text = array_intersect_key($claims, array_flip(self::TEXT_CLAIMS));

        return ($claims['sub'] ?? null) === $subject && EmailPairing::fits($claims) && array_filter($text, is_string(...)) === $text;
    }
}
