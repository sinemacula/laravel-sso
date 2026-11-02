<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Results\AssertedEmail;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;

/**
 * Pairs the email a provider asserted with its `email_verified`, from one
 * source and never one from each (SSO-7.7, SSO-8.8).
 *
 * The validated ID token is the source when it carries `email`, even when
 * UserInfo has its own; otherwise a validated UserInfo response is, when it was
 * fetched and carries `email`; otherwise there is no pair. `email_verified` is
 * read from that source alone, so another source's flag never vouches for an
 * email: JSON `true` and JSON `false` are carried as asserted, and anything
 * else (absent, `null`, a string such as `"true"`, a number, an object or an
 * array) is `null`, no evidence either way. Nothing is coerced, and such a
 * value does not refuse the sign-in.
 *
 * `fits()` is the rule on the `email` claim's type, which the UserInfo reader
 * and the claims' assembly apply before anything is paired: a string of 1 to
 * 320 bytes, when it is present. A member present as `null` is not missing, so
 * it does not fit.
 *
 * `linkingEmail()` is the only way an asserted email becomes a linking email:
 * `email_verified` exactly `true`, and one `@` between a local part and a
 * domain, by `Results\LinkingEmail`'s own rule. `organization()` reads the
 * organisation claim the connection names, from the source the email came from
 * and never another, only when it is a string a result can hold: never from the
 * email's domain or the mapped attributes. Nothing is logged here, and nothing
 * is kept between calls (SSO-11.2).
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
     * Whether the claims' `email`, when present, has the type and size the
     * package reads it with. Their `email_verified` never refuses them.
     *
     * @param  array<array-key, mixed>  $claims
     * @return bool
     */
    public static function fits(#[\SensitiveParameter] array $claims): bool
    {
        return self::isEmail($claims);
    }

    /**
     * The pair the sources assert, or `null` when neither carries an email; a
     * `null` UserInfo was not fetched. Claims `fits()` refuses are the caller's
     * mistake.
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
     * The value of the named claim in the claims of the one source the email
     * came from, or `null` when no claim is named or it is not a string of 1 to
     * 255 bytes.
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
     * The linking email the pair gives, with the organisation the same source
     * named, or `null` unless its `email_verified` is exactly `true` and its
     * email has one `@` between two non-empty parts.
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
     * The source's email with the source's own `email_verified`.
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

    /**
     * Whether `email` is absent, or a string of 1 to 320 bytes.
     *
     * @param  array<array-key, mixed>  $claims
     * @return bool
     */
    private static function isEmail(#[\SensitiveParameter] array $claims): bool
    {
        if (!array_key_exists(self::EMAIL, $claims)) {
            return true;
        }

        $email = $claims[self::EMAIL];

        return is_string($email) && $email !== '' && strlen($email) <= AssertedEmail::MAX_EMAIL_LENGTH;
    }
}
