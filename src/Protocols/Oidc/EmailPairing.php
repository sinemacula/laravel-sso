<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Results\AssertedEmail;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;

/**
 * Pairs a provider's `email` with `email_verified` from the same source, the ID
 * token first, so one source's flag never vouches for another's email.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EmailPairing
{
    /** @var string The email claim. */
    private const string EMAIL = 'email';

    /** @var string The claim that says whether the email was verified. */
    private const string EMAIL_VERIFIED = 'email_verified';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether `email` is absent or a string of 1 to 320 bytes; a `null` member
     * does not fit.
     *
     * @param  array<array-key, mixed>  $claims
     * @return bool
     */
    public static function fits(#[\SensitiveParameter] array $claims): bool
    {
        if (!array_key_exists(self::EMAIL, $claims)) {
            return true;
        }

        $email = $claims[self::EMAIL];

        return is_string($email) && $email !== '' && strlen($email) <= AssertedEmail::MAX_EMAIL_LENGTH;
    }

    /**
     * The asserted pair, or `null` when neither source carries an email; a
     * `null` UserInfo was not fetched.
     *
     * @param  array<array-key, mixed>  $idToken
     * @param  ?array<array-key, mixed>  $userInfo
     * @return ?\SineMacula\Laravel\Sso\Results\AssertedEmail
     *
     * @throws \LogicException
     */
    public static function of(#[\SensitiveParameter] array $idToken, #[\SensitiveParameter] ?array $userInfo): ?AssertedEmail
    {
        if (array_key_exists(self::EMAIL, $idToken)) {
            return self::pair($idToken, LinkingEmailSource::ID_TOKEN);
        }

        return $userInfo !== null && array_key_exists(self::EMAIL, $userInfo) ? self::pair($userInfo, LinkingEmailSource::USERINFO) : null;
    }

    /**
     * The named organisation claim from the email's source, or `null` unless it
     * is a string of 1 to 255 bytes.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  mixed  $claim
     * @return ?string
     */
    public static function organization(#[\SensitiveParameter] array $claims, mixed $claim): ?string
    {
        $value = is_string($claim) ? ($claims[$claim] ?? null) : null;

        return is_string($value) && $value !== '' && strlen($value) <= LinkingEmail::MAX_ORGANIZATION_LENGTH ? $value : null;
    }

    /**
     * The linking email, or `null` unless `email_verified` is exactly `true`
     * and the email is well formed.
     *
     * @param  ?\SineMacula\Laravel\Sso\Results\AssertedEmail  $asserted
     * @param  ?string  $organization
     * @return ?\SineMacula\Laravel\Sso\Results\LinkingEmail
     */
    public static function linkingEmail(?AssertedEmail $asserted, #[\SensitiveParameter] ?string $organization = null): ?LinkingEmail
    {
        if ($asserted?->verified !== true) {
            return null;
        }

        try {
            return new LinkingEmail($asserted->email(), $asserted->source, $organization);
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * The source's email with its own `email_verified`; a non-boolean flag is
     * `null`, never coerced.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  \SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource  $source
     * @return \SineMacula\Laravel\Sso\Results\AssertedEmail
     *
     * @throws \LogicException
     */
    private static function pair(#[\SensitiveParameter] array $claims, LinkingEmailSource $source): AssertedEmail
    {
        if (!self::fits($claims)) {
            throw new \LogicException('An email is typed before it is paired.');
        }

        $verified = $claims[self::EMAIL_VERIFIED] ?? null;

        /** @var array{email: string} $claims */
        return new AssertedEmail($claims[self::EMAIL], is_bool($verified) ? $verified : null, $source);
    }
}
