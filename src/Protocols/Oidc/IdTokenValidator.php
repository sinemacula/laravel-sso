<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Clock\ClockSkew;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Http\ClientContext;
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
 * Validates an ID token in a fixed order: parse, key, signature, then claims.
 * Not final, so a flow test can observe and answer its calls.
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
     * Validate the ID token, or refuse it. Before a JWKS refetch, the claims
     * are checked unverified so a doomed token cannot spend the cooldown.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse  $tokens
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function validate(SsoConnection $connection, OidcOptions $options, TokenResponse $tokens, ConsumedRequest $consumed, ClientContext $client): IdTokenValidation
    {
        $token = CompactToken::parse($tokens->idToken(), $this->limits->maxIdTokenBytes());

        if ($token === null) {
            return IdTokenValidation::refused(FailureReason::ID_TOKEN_INVALID);
        }

        $allowed   = $options->algorithms();
        $selection = $this->keys->select($connection, $token, $allowed, $client, $consumed, fn (): bool => $this->claimsRefusal($options, $tokens, $token, $consumed) !== null);
        $reason    = $this->signatureRefusal($selection, $token, $allowed) ?? $this->claimsRefusal($options, $tokens, $token, $consumed);

        return $reason === null ? IdTokenValidation::validated(self::validated($token), $selection->receipt) : IdTokenValidation::refused($reason);
    }

    /**
     * Why the token's key or signature refuses it, or `null`.
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
     * Why the token's claims refuse it, or `null`; the first failure answers.
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
     * Why `iss` refuses the token: it must equal both the connection's issuer
     * and the request's pinned issuer.
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
     * Why `nonce` refuses the token: its digest must be the request's.
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
     * Why `auth_time` refuses the token; a fresh authentication must follow the
     * request's start.
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
     * The validated token, with every number a number, never its digits.
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
