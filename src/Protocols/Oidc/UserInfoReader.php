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
 * Sends the UserInfo request of an OpenID Connect completion and reads what the
 * endpoint answers (SSO-2.9, SSO-7.5, SSO-7.6). A connection fetches UserInfo
 * only when it says so; then it is mandatory, so every refusal here refuses the
 * completion, and the assembly never goes on without it.
 *
 * `fetch()` makes one attempt with the access token alone, through the fetcher,
 * in the timeout and size cap of `OidcLimits`, with no retry by code or
 * middleware. It refuses to run inside a transaction on the storage connection,
 * so a provider call never holds a lock.
 *
 * `refusal()` says why the answer is refused, or `null` when its claims may be
 * read:
 *
 * - a request refused or failed is `fetch_refused` or `fetch_failed`, a timeout
 *   and a body over the request's cap among them;
 * - `401` and `403` are `provider_error`, whose code alone `providerError()`
 *   answers, from `WWW-Authenticate`, for the assembly's log;
 * - any other status outside `2xx` is `fetch_failed`;
 * - a `2xx` with the content type `application/jwt` is `userinfo_invalid`,
 *   since a signed or encrypted UserInfo response is not supported;
 * - so is a `2xx` whose body `Jose\StrictJson` does not read as an object, so a
 *   repeated member is refused; whose `sub` is not a string exactly equal, byte
 *   for byte, to the ID token's; or with a claim the package reads of another
 *   type: `email` by `EmailPairing::fits()`, and `name`, `given_name` and
 *   `family_name` strings. A number too large for an integer is never one of
 *   these strings (`StrictJson::decodeMembers()`). An `email_verified` that is
 *   not a JSON boolean refuses nothing: it is no evidence (`EmailPairing`).
 *
 * `claims()` answers the members of an answer not refused. The body is never
 * logged, and nothing here logs. It holds its collaborators, none of which
 * keeps anything of one request for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UserInfoReader
{
    /** @var list<int> The statuses of a UserInfo error response (RFC 6750 §3.1). */
    private const array PROVIDER_ERROR_STATUSES = [401, 403];

    /** @var list<string> The only codes of a bearer token error (RFC 6750 §3.1); anything else is not logged. */
    private const array ERROR_CODES = ['invalid_request', 'invalid_token', 'insufficient_scope'];

    /** @var list<string> The string claims read beside the email. */
    private const array TEXT_CLAIMS = ['name', 'given_name', 'family_name'];

    /** @var string The content type of a signed or encrypted UserInfo response. */
    private const string JWT_CONTENT_TYPE = 'application/jwt';

    /** @var string One `WWW-Authenticate` parameter (RFC 9110 §11.2): its name, and its token or quoted string. */
    private const string CHALLENGE_PARAMETER = '/([!#$%&\'*+.^_`|~0-9A-Za-z-]++)\s*+=\s*+("(?:[^"\\\]++|\\\.)*+"|[^\s,"]*+)/';

    /** @var string The challenge parameter that holds the error code. */
    private const string ERROR_PARAMETER = 'error';

    /** @var string Why a UserInfo request inside a transaction on the storage connection is refused. */
    private const string INSIDE_TRANSACTION = 'A UserInfo request is sent outside any transaction on the package\'s storage connection: a provider call never holds a lock.';

    /** @var string Why a connection that names no UserInfo endpoint is the caller's mistake. */
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
     * Send the UserInfo request, once, with the access token alone.
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
     * The bearer token error code of the answer's `WWW-Authenticate`, for the
     * log alone, or `null` when it names none of RFC 6750's. Nothing else of
     * the header is read, `error_description` above all.
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
     * The claims of an answer `refusal()` does not refuse; any other is the
     * caller's mistake.
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
     * The connection's UserInfo endpoint; a connection without one is the
     * caller's mistake.
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
     * Whether the answer's content type is `application/jwt`, whatever its case
     * or parameters.
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
     * `StrictJson` reads the object, refusing repeated members, with every
     * number a number, so one is never taken for a string of its digits.
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
     * Whether `sub` is exactly the subject and the claims read have their
     * types.
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
