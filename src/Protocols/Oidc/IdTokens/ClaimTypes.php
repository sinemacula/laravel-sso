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
 * Every claim of an ID token the package reads has its exact type (SSO-7.4,
 * `docs/design/oidc-id-tokens.md`), and anything else is `id_token_invalid`:
 * nothing is coerced, trimmed or normalised, so a later check never meets a
 * value its comparison would read two ways.
 *
 * Required:
 *
 * - `iss`: a string;
 * - `sub`: a string of 1 to 1024 bytes, kept exactly;
 * - `aud`: a non-empty string, or a non-empty JSON array of non-empty strings
 *   with no two the same;
 * - `exp` and `iat`: finite JSON numbers.
 *
 * When present, a `null` being present:
 *
 * - `nbf` and `auth_time`: finite JSON numbers;
 * - `azp`, `nonce`, `at_hash` and `email`: strings;
 * - `acr` and `sid`: strings of 1 to 1024 bytes;
 * - `amr`: a JSON array of at most 32 strings of 1 to 255 bytes.
 *
 * The rest of a token's claims are not judged, `email_verified` among them: any
 * value but a JSON boolean is no evidence of anything (`EmailPairing`) and
 * never refuses a token.
 *
 * The token's claims keep an integer too large for PHP's as its digits, so a
 * numeric date refuses it, and read a JSON object as a PHP array, so
 * `{"0":"client"}` and `["client"]` are the same value by then. `refusal()`
 * also reads the payload as JSON wrote it (`StrictJson::decodeAsWritten()`), so
 * an object is never read as a list and a number is never read as a string of
 * its digits. A number too large for a float reads as infinity, and is refused,
 * since it could never expire.
 *
 * It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ClaimTypes
{
    /** @var list<string> The claims that are strings, or lists of them, in the token's JSON. */
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
     * Whether every required claim is present with its type, and every other
     * claim the package reads is absent or has its type.
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
     * Whether every optional claim is absent or has its type.
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
     * Whether the value is a non-empty string, or a non-empty list of them with
     * no two the same.
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
     * Whether the array is a list of strings of 1 to the bytes given.
     *
     * @param  array<array-key, mixed>  $values
     * @param  int  $maxBytes
     * @return bool
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
     * Whether the value is a string of 1 to the bytes given.
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
     * Whether the value is a finite JSON number.
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
     * Whether each claim that is a string, or a list of them, is one in the
     * token's JSON: never an object read as a list, nor a number read as its
     * digits. A payload PHP cannot read as objects (a member name an object
     * cannot hold is refused by its decoder) is refused too.
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
