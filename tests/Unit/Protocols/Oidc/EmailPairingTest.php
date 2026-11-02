<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\EmailPairing;
use SineMacula\Laravel\Sso\Results\AssertedEmail;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for pairing an email with its `email_verified` (SSO-7.7, SSO-8.8):
 * every combination of the two sources, never mixed; the flag exactly as
 * asserted; the types the claims must have; and when a pair gives a linking
 * email.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EmailPairing::class)]
final class EmailPairingTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var string The email an ID token asserts. */
    private const string TOKEN_EMAIL = 'token@example.test';

    /** @var string The email a UserInfo response asserts. */
    private const string USERINFO_EMAIL = 'userinfo@example.test';

    /**
     * Rows of `[flag]`: a value of `email_verified` that is not a JSON boolean.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideNonBooleanFlags(): iterable
    {
        yield 'the string true' => ['true'];
        yield 'the string false' => ['false'];
        yield 'the string True' => ['True'];
        yield 'one' => [1];
        yield 'zero' => [0];
        yield 'a float' => [1.0];
        yield 'null' => [null];
        yield 'an object' => [['value' => true]];
        yield 'a list' => [[true]];
        yield 'an empty list' => [[]];
    }

    /**
     * A flag that is not a JSON boolean gives no evidence from either source:
     * the pair is unknown, nothing is coerced and no linking email follows, and
     * the other source's flag never stands in for it when the source has the
     * email.
     *
     * @param  mixed  $flag
     * @return void
     */
    #[DataProvider('provideNonBooleanFlags')]
    public function testANonBooleanFlagIsUnknown(mixed $flag): void
    {
        $fromToken    = EmailPairing::of(['email' => self::TOKEN_EMAIL, 'email_verified' => $flag], ['email' => self::USERINFO_EMAIL, 'email_verified' => true]);
        $fromUserInfo = EmailPairing::of(['email_verified' => true], ['email' => self::USERINFO_EMAIL, 'email_verified' => $flag]);

        self::assertSame(['email' => self::TOKEN_EMAIL, 'verified' => null, 'source' => 'id_token'], $fromToken?->toArray());
        self::assertSame(['email' => self::USERINFO_EMAIL, 'verified' => null, 'source' => 'userinfo'], $fromUserInfo?->toArray());
        self::assertNull(EmailPairing::linkingEmail($fromToken));
        self::assertNull(EmailPairing::linkingEmail($fromUserInfo));
    }

    /**
     * Rows of `[ID token, UserInfo, pair]`: every combination of the sources.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: ?array<string, mixed>, 2: ?array<string, mixed>}>
     */
    public static function providePairs(): iterable
    {
        $token    = static fn (?bool $verified): array => ['email' => self::TOKEN_EMAIL, 'verified' => $verified, 'source' => 'id_token'];
        $userInfo = static fn (?bool $verified): array => ['email' => self::USERINFO_EMAIL, 'verified' => $verified, 'source' => 'userinfo'];

        yield 'no email anywhere, UserInfo not fetched' => [[], null, null];
        yield 'no email anywhere, UserInfo fetched' => [[], ['sub' => 's'], null];

        yield 'the ID token only, verified' => [['email' => self::TOKEN_EMAIL, 'email_verified' => true], null, $token(true)];
        yield 'the ID token only, not verified' => [['email' => self::TOKEN_EMAIL, 'email_verified' => false], null, $token(false)];
        yield 'the ID token only, unknown' => [['email' => self::TOKEN_EMAIL], null, $token(null)];
        yield 'the ID token only, UserInfo fetched with no email' => [['email' => self::TOKEN_EMAIL, 'email_verified' => true], ['sub' => 's'], $token(true)];

        yield 'UserInfo only, verified' => [[], ['email' => self::USERINFO_EMAIL, 'email_verified' => true], $userInfo(true)];
        yield 'UserInfo only, not verified' => [[], ['email' => self::USERINFO_EMAIL, 'email_verified' => false], $userInfo(false)];
        yield 'UserInfo only, unknown' => [[], ['email' => self::USERINFO_EMAIL], $userInfo(null)];

        yield 'both differing, each verified' => [
            ['email' => self::TOKEN_EMAIL, 'email_verified' => true],
            ['email' => self::USERINFO_EMAIL, 'email_verified' => true],
            $token(true),
        ];
        yield 'both differing, only UserInfo verified' => [
            ['email' => self::TOKEN_EMAIL, 'email_verified' => false],
            ['email' => self::USERINFO_EMAIL, 'email_verified' => true],
            $token(false),
        ];
        yield 'both differing, only the ID token verified' => [
            ['email' => self::TOKEN_EMAIL, 'email_verified' => true],
            ['email' => self::USERINFO_EMAIL, 'email_verified' => false],
            $token(true),
        ];
        yield 'both, the ID token unknown and UserInfo vouching for the same email' => [
            ['email' => self::TOKEN_EMAIL],
            ['email' => self::TOKEN_EMAIL, 'email_verified' => true],
            $token(null),
        ];
        yield 'the flag in the ID token, the email in UserInfo' => [
            ['email_verified' => true],
            ['email' => self::USERINFO_EMAIL],
            $userInfo(null),
        ];
        yield 'a flag false in the ID token, the email and true in UserInfo' => [
            ['email_verified' => false],
            ['email' => self::USERINFO_EMAIL, 'email_verified' => true],
            $userInfo(true),
        ];
        yield 'the flag in the ID token, no email anywhere' => [['email_verified' => true], ['email_verified' => true], null];
        yield 'the email in the ID token, the flag in UserInfo alone' => [
            ['email' => self::TOKEN_EMAIL],
            ['email_verified' => true],
            $token(null),
        ];
    }

    /**
     * The pair comes from the ID token when it carries `email`, else from
     * UserInfo when that does, and is never mixed; a missing flag stays
     * unknown.
     *
     * @param  array<string, mixed>  $idToken
     * @param  ?array<string, mixed>  $userInfo
     * @param  ?array<string, mixed>  $expected
     * @return void
     */
    #[DataProvider('providePairs')]
    public function testPairsFromOneSource(array $idToken, ?array $userInfo, ?array $expected): void
    {
        self::assertSame($expected, EmailPairing::of($idToken, $userInfo)?->toArray());
    }

    /**
     * Rows of `[claims, fits]`: the claims' types and sizes.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function provideClaims(): iterable
    {
        yield 'neither' => [[], true];
        yield 'one byte' => [['email' => 'a'], true];
        yield 'at the longest' => [['email' => str_repeat('a', 320)], true];
        yield 'not an address, still a string' => [['email' => 'not-an-address'], true];
        yield 'true' => [['email_verified' => true], true];
        yield 'false' => [['email_verified' => false], true];
        yield 'both' => [['email' => 'a@b', 'email_verified' => true], true];
        yield 'an empty email' => [['email' => ''], false];
        yield 'one byte over' => [['email' => str_repeat('a', 321)], false];
        yield 'a numeric email' => [['email' => 1], false];
        yield 'a null email' => [['email' => null], false];
        yield 'a list for an email' => [['email' => ['a@b']], false];
        yield 'the string true' => [['email_verified' => 'true'], true];
        yield 'the string false' => [['email_verified' => 'false'], true];
        yield 'one' => [['email_verified' => 1], true];
        yield 'zero' => [['email_verified' => 0], true];
        yield 'a null flag' => [['email_verified' => null], true];
        yield 'an object flag' => [['email_verified' => ['a' => true]], true];
        yield 'a list flag' => [['email_verified' => [true]], true];
        yield 'a good email and a string flag' => [['email' => 'a@b', 'email_verified' => 'true'], true];
        yield 'a bad email and a good flag' => [['email' => 1, 'email_verified' => true], false];
    }

    /**
     * `email` is a string of 1 to 320 bytes when present; present as `null` is
     * not missing. Whatever `email_verified` holds never refuses the claims.
     *
     * @param  array<string, mixed>  $claims
     * @param  bool  $fits
     * @return void
     */
    #[DataProvider('provideClaims')]
    public function testJudgesTheClaimsTypes(array $claims, bool $fits): void
    {
        self::assertSame($fits, EmailPairing::fits($claims));
    }

    /**
     * Rows of `[ID token, UserInfo]`: sources whose claims do not fit, read
     * regardless.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: ?array<string, mixed>}>
     */
    public static function provideUntypedSources(): iterable
    {
        yield 'the ID token email' => [['email' => 1], null];
        yield 'the UserInfo email' => [[], ['email' => 1]];
    }

    /**
     * Pairing claims that were not typed first is the caller's mistake.
     *
     * @param  array<string, mixed>  $idToken
     * @param  ?array<string, mixed>  $userInfo
     * @return void
     */
    #[DataProvider('provideUntypedSources')]
    public function testUntypedClaimsAreTheCallersMistake(array $idToken, ?array $userInfo): void
    {
        $this->expectExceptionObject(new \LogicException('An email is typed before it is paired.'));

        EmailPairing::of($idToken, $userInfo);
    }

    /**
     * A claim named by a URI, as Slack's team is, is read by its whole name,
     * not as a path: what it holds is the organisation, and nothing else is.
     *
     * @return void
     */
    public function testAnOrganizationClaimNamedByAUriIsReadWhole(): void
    {
        $claims = ['https://slack.com/team_id' => 'T0123', 'team_id' => 'T9999'];

        self::assertSame('T0123', EmailPairing::organization($claims, 'https://slack.com/team_id'));
        self::assertNull(EmailPairing::organization(['team_id' => 'T9999'], 'https://slack.com/team_id'));
    }

    /**
     * A pair verified exactly, with one `@` between two parts, gives a linking
     * email from its own source, exactly as asserted, naming no organisation.
     *
     * @return void
     */
    public function testAVerifiedPairGivesALinkingEmail(): void
    {
        $token    = new AssertedEmail('Person+Tag@Example.COM', true, LinkingEmailSource::ID_TOKEN);
        $userInfo = new AssertedEmail(self::USERINFO_EMAIL, true, LinkingEmailSource::USERINFO);

        self::assertSame(['email' => 'Person+Tag@Example.COM', 'source' => 'id_token', 'organization' => null], EmailPairing::linkingEmail($token)?->toArray());
        self::assertSame(['email' => self::USERINFO_EMAIL, 'source' => 'userinfo', 'organization' => null], EmailPairing::linkingEmail($userInfo)?->toArray());
    }

    /**
     * Rows of `[pair]`: pairs that give no linking email.
     *
     * @return iterable<string, array{0: ?\SineMacula\Laravel\Sso\Results\AssertedEmail}>
     */
    public static function provideUnlinkablePairs(): iterable
    {
        yield 'no pair' => [null];
        yield 'not verified' => [new AssertedEmail(self::TOKEN_EMAIL, false, LinkingEmailSource::ID_TOKEN)];
        yield 'unknown' => [new AssertedEmail(self::TOKEN_EMAIL, null, LinkingEmailSource::ID_TOKEN)];
        yield 'no @' => [new AssertedEmail('person', true, LinkingEmailSource::ID_TOKEN)];
        yield 'no local part' => [new AssertedEmail('@example.test', true, LinkingEmailSource::ID_TOKEN)];
        yield 'no domain' => [new AssertedEmail('person@', true, LinkingEmailSource::USERINFO)];
        yield 'two @' => [new AssertedEmail('a@b@example.test', true, LinkingEmailSource::USERINFO)];
    }

    /**
     * Anything but a pair verified exactly, with one `@` between two parts,
     * gives no linking email, and never throws.
     *
     * @param  ?\SineMacula\Laravel\Sso\Results\AssertedEmail  $asserted
     * @return void
     */
    #[DataProvider('provideUnlinkablePairs')]
    public function testOtherPairsGiveNoLinkingEmail(?AssertedEmail $asserted): void
    {
        self::assertNull(EmailPairing::linkingEmail($asserted));
        self::assertNull(EmailPairing::linkingEmail(null));
    }
}
