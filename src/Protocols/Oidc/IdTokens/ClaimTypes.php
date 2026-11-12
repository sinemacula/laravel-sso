<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\StrictJson;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\TimeClaims;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The exact type of every ID token claim the package reads; nothing is coerced,
 * trimmed or normalised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ClaimTypes
{
    /** @var list<string> The claims that must be strings, or lists of them, as written. */
    private const array TEXT_CLAIMS = ['iss', 'sub', 'aud', 'azp', 'nonce', 'at_hash', 'email', 'acr', 'sid', 'amr'];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Why the token's claims refuse it, or `null` when each has its type.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken  $token
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public static function refusal(CompactToken $token): ?FailureReason
    {
        return self::areTyped($token->claims()) && self::isTextAsWritten($token) ? null : FailureReason::ID_TOKEN_INVALID;
    }

    /**
     * Whether every required claim is typed and every optional one is absent or
     * typed.
     *
     * @param  array<array-key, mixed>  $claims
     * @return bool
     */
    public static function areTyped(#[\SensitiveParameter] array $claims): bool
    {
        $required = [
            is_string($claims['iss'] ?? null),
            self::isText($claims['sub'] ?? null, VerifiedResult::MAX_SUBJECT_LENGTH),
            self::isAudience($claims['aud'] ?? null),
            self::isNumericDate($claims['exp'] ?? null),
            self::isNumericDate($claims['iat'] ?? null),
        ];

        return !in_array(false, $required, true) && self::areOptionalClaimsTyped($claims);
    }

    /**
     * Whether every optional claim is absent or typed; a `null` counts as
     * present.
     *
     * @param  array<array-key, mixed>  $claims
     * @return bool
     */
    private static function areOptionalClaimsTyped(#[\SensitiveParameter] array $claims): bool
    {
        $rules = [
            'nbf'       => self::isNumericDate(...),
            'auth_time' => self::isNumericDate(...),
            'azp'       => is_string(...),
            'nonce'     => is_string(...),
            'at_hash'   => is_string(...),
            'email'     => is_string(...),
            'acr'       => static fn (#[\SensitiveParameter] mixed $value): bool => self::isContextValue($value),
            'sid'       => static fn (#[\SensitiveParameter] mixed $value): bool => self::isContextValue($value),
            'amr'       => static fn (#[\SensitiveParameter] mixed $value): bool => self::isMethods($value),
        ];

        foreach ($rules as $name => $rule) {
            if (array_key_exists($name, $claims) && !$rule($claims[$name])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether the value is a non-empty string or a non-empty list of distinct
     * ones.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isAudience(#[\SensitiveParameter] mixed $value): bool
    {
        if (is_string($value)) {
            return $value !== '';
        }

        if (!is_array($value) || $value === [] || !self::isListOfText($value, PHP_INT_MAX)) {
            return false;
        }

        return array_unique($value) === $value;
    }

    /**
     * Whether the value is a list of at most 32 strings of 1 to 255 bytes.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isMethods(#[\SensitiveParameter] mixed $value): bool
    {
        return is_array($value) && count($value) <= AuthenticationContext::MAX_METHODS && self::isListOfText($value, AuthenticationContext::MAX_METHOD_LENGTH);
    }

    /**
     * Whether the array is a list of strings of 1 to `$maxBytes` bytes.
     *
     * @param  array<array-key, mixed>  $values
     * @param  int  $maxBytes
     * @return bool
     *
     * @phpstan-assert-if-true list<non-empty-string> $values
     */
    private static function isListOfText(#[\SensitiveParameter] array $values, int $maxBytes): bool
    {
        return array_is_list($values) && array_filter($values, static fn (mixed $value): bool => self::isText($value, $maxBytes)) === $values;
    }

    /**
     * Whether the value is a string of 1 to 1024 bytes, as `acr` and `sid` are.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isContextValue(#[\SensitiveParameter] mixed $value): bool
    {
        return self::isText($value, AuthenticationContext::MAX_VALUE_LENGTH);
    }

    /**
     * Whether the value is a string of 1 to `$maxBytes` bytes.
     *
     * @param  mixed  $value
     * @param  int  $maxBytes
     * @return bool
     */
    private static function isText(#[\SensitiveParameter] mixed $value, int $maxBytes): bool
    {
        return is_string($value) && $value !== '' && strlen($value) <= $maxBytes;
    }

    /**
     * Whether the value is a finite JSON number; infinity could never expire.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isNumericDate(#[\SensitiveParameter] mixed $value): bool
    {
        $seconds = TimeClaims::numericDate($value);

        return $seconds !== null && is_finite($seconds);
    }

    /**
     * Whether each string claim is a string as written in the JSON, never an
     * object read as a list or a number read as its digits.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken  $token
     * @return bool
     */
    private static function isTextAsWritten(CompactToken $token): bool
    {
        $written = StrictJson::decodeAsWritten($token->payload());

        if ($written === null) {
            return false;
        }

        foreach (self::TEXT_CLAIMS as $name) {

            $value = $written->{$name} ?? [];

            if ($value instanceof \stdClass || !self::holdsOnlyStrings((array) $value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether every value is a string.
     *
     * @param  array<array-key, mixed>  $values
     * @return bool
     */
    private static function holdsOnlyStrings(#[\SensitiveParameter] array $values): bool
    {
        return array_filter($values, is_string(...)) === $values;
    }
}
