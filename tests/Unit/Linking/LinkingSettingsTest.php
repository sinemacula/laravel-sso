<?php

declare(strict_types = 1);

namespace Tests\Unit\Linking;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Linking\LinkingCheck;
use SineMacula\Laravel\Sso\Linking\LinkingSettings;
use SineMacula\Laravel\Sso\Protocols\Preset;
use SineMacula\Laravel\Sso\Protocols\Presets;

/**
 * Unit tests for `sso.linking` (SSO-8.6, SSO-8.7, SSO-8.8): each maximum age's
 * default and bounds, at one under, at and one over; the shared issuers, which
 * configuration adds to and never downgrades; the boot check; and the presets,
 * whose shared issuers agree with the settings, and which know their issuers
 * exactly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkingSettings::class)]
#[CoversClass(LinkingCheck::class)]
#[CoversClass(Preset::class)]
#[CoversClass(Presets::class)]
final class LinkingSettingsTest extends TestCase
{
    /**
     * Unset, each is its default, and the shared issuers are the built-in ones.
     *
     * @return void
     */
    public function testTheDefaults(): void
    {
        $settings = self::settings([]);

        self::assertSame(120, $settings->verifiedResultMaxAgeSeconds());
        self::assertSame(900, $settings->evidenceMaxAgeSeconds());
        self::assertSame(['https://accounts.google.com' => 'hd', 'accounts.google.com' => 'hd'], $settings->sharedIssuers());
    }

    /**
     * Rows of `[seconds, whether it is accepted]`: the verified response's
     * validity, 5 to 300 seconds.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideVerifiedAges(): iterable
    {
        yield 'one under the least' => [4, false];
        yield 'the least' => [5, true];
        yield 'one over the least' => [6, true];
        yield 'one under the most' => [299, true];
        yield 'the most' => [300, true];
        yield 'one over the most' => [301, false];
    }

    /**
     * The verified response's validity is held to its bounds, naming its key.
     *
     * @param  int  $seconds
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideVerifiedAges')]
    public function testTheVerifiedResultMaxAgeIsBounded(int $seconds, bool $accepted): void
    {
        $settings = self::settings(['verified_result_max_age_seconds' => $seconds]);

        if (!$accepted) {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessage('sso.linking.verified_result_max_age_seconds must be an integer from 5 to 300.');
        }

        self::assertSame($seconds, $settings->verifiedResultMaxAgeSeconds());
    }

    /**
     * Rows of `[seconds, whether it is accepted]`: the evidence's maximum age,
     * 60 to 3600 seconds.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideEvidenceAges(): iterable
    {
        yield 'one under the least' => [59, false];
        yield 'the least' => [60, true];
        yield 'one over the least' => [61, true];
        yield 'one under the most' => [3599, true];
        yield 'the most' => [3600, true];
        yield 'one over the most' => [3601, false];
    }

    /**
     * The evidence's maximum age is held to its bounds, naming its key.
     *
     * @param  int  $seconds
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideEvidenceAges')]
    public function testTheEvidenceMaxAgeIsBounded(int $seconds, bool $accepted): void
    {
        $settings = self::settings(['evidence_max_age_seconds' => $seconds]);

        if (!$accepted) {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessage('sso.linking.evidence_max_age_seconds must be an integer from 60 to 3600.');
        }

        self::assertSame($seconds, $settings->evidenceMaxAgeSeconds());
    }

    /**
     * Configuration adds a shared issuer; an entry for a built-in one changes
     * nothing, so none can be downgraded.
     *
     * @return void
     */
    public function testConfigurationAddsAndNeverDowngrades(): void
    {
        $settings = self::settings(['shared_issuers' => ['https://shared.example.com' => 'org', 'https://accounts.google.com' => 'not-hd', 'accounts.google.com' => 'not-hd']]);

        self::assertSame([
            'https://shared.example.com'  => 'org',
            'https://accounts.google.com' => 'hd',
            'accounts.google.com'         => 'hd',
        ], $settings->sharedIssuers());
    }

    /**
     * Rows of `[shared issuers]`: what the setting refuses.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedIssuers(): iterable
    {
        yield 'not a map' => ['https://shared.example.com'];
        yield 'a list' => [['org']];
        yield 'an empty issuer' => [['' => 'org']];
        yield 'an empty claim' => [['https://shared.example.com' => '']];
        yield 'a claim that is no string' => [['https://shared.example.com' => true]];
    }

    /**
     * A malformed list of shared issuers fails closed, naming its key.
     *
     * @param  mixed  $issuers
     * @return void
     */
    #[DataProvider('provideMalformedIssuers')]
    public function testMalformedSharedIssuersAreRefused(mixed $issuers): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('sso.linking.shared_issuers must map each issuer to its organisation claim.');

        self::settings(['shared_issuers' => $issuers])->sharedIssuers();
    }

    /**
     * The check reads each setting, and a malformed one fails when it runs.
     *
     * @return void
     */
    public function testTheCheckReadsEverySetting(): void
    {
        $linking    = ['verified_result_max_age_seconds' => 10, 'evidence_max_age_seconds' => 70, 'shared_issuers' => ['https://shared.example.com' => 'org']];
        $repository = new Repository(['sso' => ['linking' => $linking]]);
        $answers    = array_map(static fn (\Closure $check): mixed => $check(), (new LinkingCheck($repository))->checks());

        self::assertSame([10, 70, ['https://shared.example.com' => 'org', 'https://accounts.google.com' => 'hd', 'accounts.google.com' => 'hd']], $answers);
    }

    /**
     * The `google` preset and the settings' shared issuers agree.
     *
     * @return void
     */
    public function testTheGooglePresetAndTheSharedIssuersAgree(): void
    {
        $google = Presets::shipped()['google'];

        self::assertSame('hd', $google->organizationClaim);
        self::assertTrue($google->isSharedIssuer());
        $issuer = $google->settings['issuer'];

        self::assertIsString($issuer);
        self::assertSame($google->organizationClaim, LinkingSettings::SHARED_ISSUERS[$issuer]);
    }

    /**
     * Every shipped preset with an organisation claim, and only those, is for a
     * shared issuer.
     *
     * @return void
     */
    public function testWhichPresetsAreForSharedIssuers(): void
    {
        $claims = array_map(static fn (Preset $preset): ?string => $preset->organizationClaim, Presets::shipped());

        self::assertSame([
            'google'               => 'hd',
            'microsoft_entra'      => 'tid',
            'okta'                 => null,
            'auth0'                => null,
            'microsoft_entra_saml' => 'http://schemas.microsoft.com/identity/claims/tenantid',
        ], $claims);
    }

    /**
     * Rows of `[preset, issuer, whether it is the preset's]`: an issuer filled
     * in is matched exactly, and a pattern of a directory's issuer to the end.
     *
     * @return iterable<string, array{0: string, 1: string, 2: bool}>
     */
    public static function provideIssuers(): iterable
    {
        yield 'google' => ['google', 'https://accounts.google.com', true];
        yield 'google, a prefix' => ['google', 'https://accounts.google.com/', false];
        yield 'google, in another case' => ['google', 'https://Accounts.Google.com', false];
        yield 'entra v2' => ['microsoft_entra', 'https://login.microsoftonline.com/the-directory/v2.0', true];
        yield 'entra v1' => ['microsoft_entra', 'https://sts.windows.net/the-directory/', true];
        yield 'entra, no directory' => ['microsoft_entra', 'https://login.microsoftonline.com//v2.0', false];
        yield 'entra, another host' => ['microsoft_entra', 'https://login.example.com/the-directory/v2.0', false];
        yield 'entra, over http' => ['microsoft_entra', 'http://sts.windows.net/the-directory/', false];
        yield 'entra, more after it' => ['microsoft_entra', 'https://sts.windows.net/the-directory/more', false];
        yield 'entra, a new line after it' => ['microsoft_entra', "https://sts.windows.net/the-directory/\n", false];
        yield 'entra over saml' => ['microsoft_entra_saml', 'https://sts.windows.net/the-directory/', true];
        yield 'entra over saml, the OIDC issuer' => ['microsoft_entra_saml', 'https://login.microsoftonline.com/the-directory/v2.0', false];
        yield 'okta names none' => ['okta', 'https://example.okta.com', false];
    }

    /**
     * Whether an issuer is a preset's.
     *
     * @param  string  $preset
     * @param  string  $issuer
     * @param  bool  $named
     * @return void
     */
    #[DataProvider('provideIssuers')]
    public function testWhichIssuersAPresetNames(string $preset, string $issuer, bool $named): void
    {
        self::assertSame($named, Presets::shipped()[$preset]->names($issuer));
    }

    /**
     * A preset filling in a SAML entity id names exactly it.
     *
     * @return void
     */
    public function testAPresetNamesTheEntityIdItFillsIn(): void
    {
        $preset = new Preset('acme', 'saml2', ['idp_entity_id' => 'https://idp.example.com'], [], 'org');

        self::assertTrue($preset->names('https://idp.example.com'));
        self::assertFalse($preset->names('https://idp.example.com/'));
        self::assertNull($preset->issuerPattern);
    }

    /**
     * Settings of the values given under `sso.linking`.
     *
     * @param  array<string, mixed>  $values
     * @return \SineMacula\Laravel\Sso\Linking\LinkingSettings
     */
    private static function settings(array $values): LinkingSettings
    {
        return new LinkingSettings(new Repository(['sso' => ['linking' => $values]]));
    }
}
