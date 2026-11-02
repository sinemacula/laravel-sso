<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Clock\ClockSkew;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Metadata\ProviderKeys;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens\AccessTokenHash;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens\AudienceRules;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens\AuthenticationTimeRules;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens\ClaimTypes;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\JoseAdapter;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\TimeClaims;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken;

/**
 * Validates the ID token of a token response against the connection and the
 * consumed request (SSO-7.3, SSO-7.4, SSO-5.10). The checks run in this fixed
 * order, and the first that fails answers:
 *
 * 1. `Jose\CompactToken::parse()` under `OidcLimits::maxIdTokenBytes()`: a
 *    token it does not read is `id_token_invalid`;
 * 2. the key, from the connection's stored JWKS (`Metadata\ProviderKeys`, which
 *    refetches once on an unknown `kid`): only a key found goes on, unknown or
 *    refused is `signature_invalid`, and a connection gone or a trust change
 *    found while looking is `connection_unavailable`, as the completion's locks
 *    would have answered. Before a refetch, steps 4 to 10 run on the token's
 *    unverified claims, for rejection only: a token that would be refused
 *    anyway fetches nothing and leaves the shared cooldown unclaimed, answered
 *    `signature_invalid` like any token no key the connection holds verifies,
 *    so the answer says nothing of its claims. Unverified claims never
 *    establish identity or choose a URL to fetch, and every step runs again
 *    after the signature;
 * 3. the signature, `Jose\JoseAdapter::verify()`, under the connection's
 *    allow-list: `signature_invalid`;
 * 4. every claim the package reads has its exact type
 *    (`IdTokens\ClaimTypes`): `id_token_invalid`;
 * 5. `iss` is the connection's issuer and the issuer the request pinned, each
 *    exactly: `issuer_mismatch`;
 * 6. `aud` and `azp` (`IdTokens\AudienceRules`): `audience_mismatch`;
 * 7. `exp`, `iat` and `nbf` (`Jose\TimeClaims`), against the package's clock
 *    and skew, never the library's: `assertion_expired`;
 * 8. `nonce`, a string of 1 to 512 bytes whose digest is the one the request
 *    stored, compared in constant time; none is `nonce_mismatch`;
 * 9. `auth_time` (`IdTokens\AuthenticationTimeRules`), under the connection's
 *    `max_age` and, for a `reauthenticate` or a `max_age` of 0, not before the
 *    request started less the skew, never relative to when the callback runs;
 * 10. `at_hash` when present (`IdTokens\AccessTokenHash`): `at_hash_mismatch`.
 *
 * A claim decides a refusal only once the signature has verified with a key the
 * connection holds, so no refusal says anything of a token that is not the
 * provider's.
 *
 * A token validated under keys its own refetch rotated carries that refetch's
 * `Protocols\TransitionReceipt` on: it is handed on only here, once every step
 * has passed under the keys the rotation left.
 *
 * It runs outside any transaction, since the refetch fetches. A database error,
 * a misconfigured limit and a misconfigured allow-list propagate (SSO-11.4). It
 * logs nothing and puts nothing of the token in an exception (SSO-7.6). It
 * holds the key reader, the adapter, the limits and the clock, none of which
 * keeps anything of one call for the next, and reads the skew and the limits on
 * each call (SSO-11.2). It is not final, so a test of the flow around it can
 * observe and answer its calls.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 */
readonly class IdTokenValidator
{
    /** @var int The longest `nonce` a token may carry, in bytes. */
    private const int MAX_NONCE_BYTES = 512;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\ProviderKeys  $keys
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\JoseAdapter  $jose
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits  $limits
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Chooses the key from the connection's stored JWKS. */
        private ProviderKeys $keys,

        /** Checks the signature with the key chosen. */
        private JoseAdapter $jose,

        /** The ID token's size cap and the oldest `iat`. */
        private OidcLimits $limits,

        /** The clock every time claim is judged against. */
        private Clock $clock,
    ) {}

    /**
     * Validate the token response's ID token, or refuse it.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse  $tokens
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function validate(SsoConnection $connection, OidcOptions $options, TokenResponse $tokens, ConsumedRequest $consumed): IdTokenValidation
    {
        $token = CompactToken::parse($tokens->idToken(), $this->limits->maxIdTokenBytes());

        if ($token === null) {
            return IdTokenValidation::refused(FailureReason::ID_TOKEN_INVALID);
        }

        $allowed   = $options->algorithms();
        $selection = $this->keys->select($connection, $token, $allowed, $consumed, fn (): bool => $this->claimsRefusal($options, $tokens, $token, $consumed) !== null);
        $reason    = $this->signatureRefusal($selection, $token, $allowed) ?? $this->claimsRefusal($options, $tokens, $token, $consumed);

        return $reason === null ? IdTokenValidation::validated(self::validated($token), $selection->receipt) : IdTokenValidation::refused($reason);
    }

    /**
     * Why the token's key or signature refuses it (steps 2 and 3), or `null`.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection  $selection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken  $token
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function signatureRefusal(KeySelection $selection, CompactToken $token, AlgorithmAllowList $allowed): ?FailureReason
    {
        if ($selection->isOvertaken()) {
            return FailureReason::CONNECTION_UNAVAILABLE;
        }

        $verified = $selection->isFound() && $this->jose->verify($token, $selection->key, $allowed);

        return $verified ? null : FailureReason::SIGNATURE_INVALID;
    }

    /**
     * Why the verified token's claims refuse it (steps 4 to 10), or `null`, the
     * first failure answering.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse  $tokens
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken  $token
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function claimsRefusal(OidcOptions $options, TokenResponse $tokens, CompactToken $token, ConsumedRequest $consumed): ?FailureReason
    {
        $claims = $token->claims();
        $now    = $this->clock->now();
        $skew   = ClockSkew::seconds();

        return ClaimTypes::refusal($token)
            ?? self::issuerRefusal($claims, $options, $consumed)
            ?? AudienceRules::refusal($claims, $options->clientId(), $options->trustedAudiences())
            ?? TimeClaims::check($claims, $now, $skew, $this->limits->idTokenMaxAgeSeconds())
            ?? self::nonceRefusal($claims, $consumed)
            ?? self::authenticationTimeRefusal($claims, $now, $skew, $options, $consumed)
            ?? AccessTokenHash::refusal($claims, $tokens->accessToken(), $token->algorithm());
    }

    /**
     * Why `iss` refuses the token: it must be the connection's issuer and the
     * issuer the request pinned, each exactly.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    private static function issuerRefusal(#[\SensitiveParameter] array $claims, OidcOptions $options, ConsumedRequest $consumed): ?FailureReason
    {
        $issuer     = $claims['iss'] ?? null;
        $configured = $issuer === $options->issuer();
        $pinned     = $issuer === $consumed->expectedIssuer;

        return $configured && $pinned ? null : FailureReason::ISSUER_MISMATCH;
    }

    /**
     * Why `nonce` refuses the token: it must be a string of 1 to 512 bytes
     * whose digest is the one the request stored.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function nonceRefusal(#[\SensitiveParameter] array $claims, ConsumedRequest $consumed): ?FailureReason
    {
        $nonce  = $claims['nonce'] ?? null;
        $shaped = is_string($nonce) && $nonce !== '' && strlen($nonce) <= self::MAX_NONCE_BYTES;

        return $shaped && $consumed->isNonce($nonce) ? null : FailureReason::NONCE_MISMATCH;
    }

    /**
     * Why `auth_time` refuses the token, under the connection's `max_age` and,
     * for a `reauthenticate` or a `max_age` of 0, which each ask the provider
     * to authenticate afresh, when the request started.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $skewSeconds
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function authenticationTimeRefusal(
        #[\SensitiveParameter] array $claims,
        CarbonImmutable $now,
        int $skewSeconds,
        OidcOptions $options,
        ConsumedRequest $consumed,
    ): ?FailureReason {
        $maxAge = $options->maxAge();
        $afresh = $consumed->purpose === Purpose::REAUTHENTICATE || $maxAge === 0;

        return AuthenticationTimeRules::refusal($claims, $now, $skewSeconds, $maxAge, $afresh ? $consumed->startedAt : null);
    }

    /**
     * The token as validated: its issuer and subject known to be strings, and
     * every number among its claims a number, never its digits.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken  $token
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken
     *
     * @throws \InvalidArgumentException
     */
    private static function validated(CompactToken $token): ValidatedIdToken
    {
        /** @var array{iss: string, sub: string} $claims */
        $claims = $token->members();

        return new ValidatedIdToken($claims['iss'], $claims['sub'], $claims);
    }
}
