<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use Carbon\CarbonImmutable;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Connections\AttributeMapping;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\TimeClaims;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken;
use SineMacula\Laravel\Sso\Results\AssertedEmail;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Builds what an OpenID Connect completion verified from the validated ID token
 * and, when the connection fetches it, its UserInfo response (SSO-7.5, SSO-7.6,
 * SSO-7.7, SSO-8.1).
 *
 * When the connection fetches UserInfo it is read first, and mandatory: a
 * refusal is the completion's (`UserInfoReader`), with no fallback to the ID
 * token alone. A `provider_error` is logged by its bearer token error code
 * alone, under `sso.oidc.userinfo_error`, never a body or a description.
 *
 * From what passed:
 *
 * - the issuer, the subject and the authentication context come from the ID
 *   token alone, whatever UserInfo says: `auth_time` at full precision, `amr`,
 *   `acr` and `sid`. OIDC states no session deadline. A claim that does not fit
 *   what a result holds is `id_token_invalid`, never an exception, though the
 *   ID token's validation has typed them;
 * - the raw attributes are the ID token's claims with UserInfo's laid over
 *   them, so UserInfo wins, less every name
 *   `AttributeMapping::RESERVED_OIDC_SOURCES` lists, from either source; their
 *   `email` is the pair's, or is removed when there is none, so a mapped email
 *   and the asserted one never disagree;
 * - the pair of `email` and `email_verified` comes from one source
 *   (`EmailPairing`), and is carried as asserted. It gives a linking email only
 *   when `email_verified` is exactly `true`, with no organisation.
 *
 * It answers with no replay record: the single use of the request and of the
 * code stand in for one. It reports no event, since the pipeline reports the
 * completion. The access token is used for the UserInfo request alone and
 * nothing keeps a token (SSO-7.6). It holds its collaborators, none of which
 * keeps anything of one completion for the next (SSO-11.2). It is not final, so
 * a test of the flow around it can observe and answer its calls.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 */
readonly class ClaimsAssembler
{
    /** @var string The log message of an error the UserInfo endpoint answered. */
    private const string USERINFO_ERROR = 'sso.oidc.userinfo_error';

    /** @var string What is logged when the endpoint named no bearer token error code. */
    private const string UNRECOGNIZED_ERROR = '[unrecognized]';

    /** @var string The form an `auth_time` is read in, to the microsecond. */
    private const string NUMERIC_DATE_FORMAT = 'U.u';

    /** @var float The latest `auth_time` a result can store: the last second of the year 9999. */
    private const float LATEST_AUTHENTICATION_TIME = 253402300799.0;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\UserInfoReader  $userInfo
     * @param  \Psr\Log\LoggerInterface  $logger
     */
    public function __construct(

        /** Sends the UserInfo request and reads its answer. */
        private UserInfoReader $userInfo,

        /** The sanitising logger. */
        private LoggerInterface $logger,
    ) {}

    /**
     * Build the verified claims, or refuse them.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken  $idToken
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse  $tokens
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \LogicException
     * @throws \InvalidArgumentException
     */
    public function assemble(SsoConnection $connection, OidcOptions $options, ValidatedIdToken $idToken, TokenResponse $tokens, ConsumedRequest $consumed): Completion
    {
        if (!$options->fetchesUserInfo()) {
            return self::verified($idToken, null);
        }

        $fetched = $this->userInfo->fetch($options, $tokens);
        $reason  = $this->userInfo->refusal($fetched, $idToken);

        if ($reason !== null) {
            $this->logRefusal($connection, $consumed, $fetched, $reason);

            return Completion::refused($reason);
        }

        return self::verified($idToken, $this->userInfo->claims($fetched, $idToken));
    }

    /**
     * Log a provider's error by its code alone, naming the request by its
     * public reference; any other refusal logs nothing here.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $fetched
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    private function logRefusal(SsoConnection $connection, ConsumedRequest $consumed, FetchResult $fetched, FailureReason $reason): void
    {
        if ($reason !== FailureReason::PROVIDER_ERROR) {
            return;
        }

        $this->logger->notice(self::USERINFO_ERROR, [
            'connection_id'     => $connection->getConnectionId(),
            'request_reference' => $consumed->reference->value,
            'error'             => $this->userInfo->providerError($fetched) ?? self::UNRECOGNIZED_ERROR,
        ]);
    }

    /**
     * The verified claims of the ID token and UserInfo's claims, `null` when it
     * was not fetched, or `id_token_invalid` when the token's claims do not
     * fit.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken  $idToken
     * @param  ?array<array-key, mixed>  $userInfo
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \LogicException
     */
    private static function verified(ValidatedIdToken $idToken, #[\SensitiveParameter] ?array $userInfo): Completion
    {
        $claims = $idToken->claims();

        if (!self::fits($idToken, $claims)) {
            return Completion::refused(FailureReason::ID_TOKEN_INVALID);
        }

        $asserted = EmailPairing::of($claims, $userInfo);

        return Completion::verified(new VerifiedClaims(
            issuer: $idToken->issuer,
            subject: $idToken->subject(),
            nameIdFormat: null,
            attributes: self::attributes($claims, $userInfo, $asserted),
            authenticationContext: self::context($claims),
            linkingEmail: EmailPairing::linkingEmail($asserted),
            assertedEmail: $asserted,
        ));
    }

    /**
     * Whether every part of the ID token the claims are built from fits what a
     * result holds.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken  $idToken
     * @param  array<array-key, mixed>  $claims
     * @return bool
     */
    private static function fits(ValidatedIdToken $idToken, #[\SensitiveParameter] array $claims): bool
    {
        $checks = [
            self::isText($idToken->issuer, VerifiedResult::MAX_ISSUER_LENGTH),
            self::isText($idToken->subject(), VerifiedResult::MAX_SUBJECT_LENGTH),
            EmailPairing::fits($claims),
            self::isAuthenticationTime($claims),
            self::isMethods($claims),
            self::isOptionalText($claims, 'acr'),
            self::isOptionalText($claims, 'sid'),
        ];

        return !in_array(false, $checks, true);
    }

    /**
     * The raw attributes the mapping reads: the ID token's claims with
     * UserInfo's over them, less the protocol values and tokens, and the pair's
     * email alone under `email`.
     *
     * @param  array<array-key, mixed>  $idToken
     * @param  ?array<array-key, mixed>  $userInfo
     * @param  ?\SineMacula\Laravel\Sso\Results\AssertedEmail  $asserted
     * @return array<string, mixed>
     */
    private static function attributes(#[\SensitiveParameter] array $idToken, #[\SensitiveParameter] ?array $userInfo, ?AssertedEmail $asserted): array
    {
        /** @var array<string, mixed> $attributes */
        $attributes = array_diff_key(array_replace($idToken, $userInfo ?? []), array_flip([...AttributeMapping::RESERVED_OIDC_SOURCES, 'email']));

        return $asserted === null ? $attributes : array_replace($attributes, ['email' => $asserted->email()]);
    }

    /**
     * The authentication context the ID token states, its claims known to fit.
     *
     * @param  array<array-key, mixed>  $claims
     * @return \SineMacula\Laravel\Sso\Results\AuthenticationContext
     */
    private static function context(#[\SensitiveParameter] array $claims): AuthenticationContext
    {
        /** @var array{amr?: list<string>, acr?: string, sid?: string} $claims */
        return new AuthenticationContext(
            authenticatedAt: self::authenticatedAt($claims),
            methods: $claims['amr']           ?? [],
            contextClass: $claims['acr']      ?? null,
            providerSessionId: $claims['sid'] ?? null,
            providerSessionDeadline: null,
        );
    }

    /**
     * When the ID token says the person authenticated, at full precision, or
     * `null` when it does not say.
     *
     * @param  array<array-key, mixed>  $claims
     * @return ?\Carbon\CarbonImmutable
     */
    private static function authenticatedAt(#[\SensitiveParameter] array $claims): ?CarbonImmutable
    {
        $seconds = TimeClaims::numericDate($claims['auth_time'] ?? null);

        return $seconds === null ? null : CarbonImmutable::createFromFormat(self::NUMERIC_DATE_FORMAT, sprintf('%.6F', $seconds), 'UTC')?->utc();
    }

    /**
     * Whether `auth_time` is absent, or a number a result can store.
     *
     * @param  array<array-key, mixed>  $claims
     * @return bool
     */
    private static function isAuthenticationTime(#[\SensitiveParameter] array $claims): bool
    {
        if (!array_key_exists('auth_time', $claims)) {
            return true;
        }

        $seconds = TimeClaims::numericDate($claims['auth_time']);

        return $seconds !== null && $seconds >= 0.0 && $seconds <= self::LATEST_AUTHENTICATION_TIME;
    }

    /**
     * Whether `amr` is absent, or a list of at most 32 strings of 1 to 255
     * bytes.
     *
     * @param  array<array-key, mixed>  $claims
     * @return bool
     */
    private static function isMethods(#[\SensitiveParameter] array $claims): bool
    {
        if (!array_key_exists('amr', $claims)) {
            return true;
        }

        $methods = $claims['amr'];

        if (!is_array($methods) || !array_is_list($methods) || count($methods) > AuthenticationContext::MAX_METHODS) {
            return false;
        }

        return array_filter($methods, static fn (mixed $method): bool => self::isText($method, AuthenticationContext::MAX_METHOD_LENGTH)) === $methods;
    }

    /**
     * Whether the claim is absent, or a string of 1 to 1024 bytes.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  string  $name
     * @return bool
     */
    private static function isOptionalText(#[\SensitiveParameter] array $claims, string $name): bool
    {
        return !array_key_exists($name, $claims) || self::isText($claims[$name], AuthenticationContext::MAX_VALUE_LENGTH);
    }

    /**
     * Whether the value is a string of 1 to the bytes allowed.
     *
     * @param  mixed  $value
     * @param  int  $maxBytes
     * @return bool
     */
    private static function isText(#[\SensitiveParameter] mixed $value, int $maxBytes): bool
    {
        return is_string($value) && $value !== '' && strlen($value) <= $maxBytes;
    }
}
