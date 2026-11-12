<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use Tests\TestCase;

/**
 * Feature tests holding every connection setting to the rule that none turns a
 * check off.
 *
 * A new setting fails until placed; a `chooses` one needs a weakening row or a
 * `PROVEN_ELSEWHERE` entry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Saml2Setting::class)]
#[CoversClass(OidcSetting::class)]
final class SettingsInventoryTest extends TestCase
{
    /** @var array<string, string> Every SAML connection setting and what it does to the checks. */
    private const array SAML = [
        'idp_entity_id'                  => 'identifies',
        'sso_url'                        => 'requests',
        'sso_binding'                    => 'requests',
        'subject_source'                 => 'identifies',
        'subject_attribute'              => 'identifies',
        'name_id_format'                 => 'chooses',
        'sign_authn_requests'            => 'requests',
        'want_assertions_signed'         => 'chooses',
        'require_encrypted_assertions'   => 'tightens',
        'signature_algorithms'           => 'chooses',
        'encryption_algorithms'          => 'chooses',
        'force_authn'                    => 'requests',
        'requested_authn_context'        => 'tightens',
        'max_authentication_age_seconds' => 'tightens',
        'idp_initiated'                  => 'chooses',
        'idp_initiated_start_url'        => 'requests',
        'metadata_url'                   => 'identifies',
        'metadata_refresh'               => 'chooses',
    ];

    /** @var array<string, string> Every OIDC connection setting and what it does to the checks. */
    private const array OIDC = [
        'issuer'                     => 'identifies',
        'authorization_endpoint'     => 'requests',
        'token_endpoint'             => 'requests',
        'jwks_uri'                   => 'identifies',
        'userinfo_endpoint'          => 'requests',
        'returns_iss'                => 'tightens',
        'client_id'                  => 'identifies',
        'client_secret'              => 'requests',
        'client_authentication'      => 'chooses',
        'client_assertion_algorithm' => 'chooses',
        'scopes'                     => 'requests',
        'id_token_algorithms'        => 'chooses',
        'extra_parameters'           => 'chooses',
        'trusted_audiences'          => 'chooses',
        'max_age'                    => 'tightens',
        'fetch_userinfo'             => 'tightens',
        'metadata_refresh'           => 'chooses',
    ];

    /** @var array<string, string> The `chooses` settings whose floor another test proves, with that test and why. */
    private const array PROVEN_ELSEWHERE = [
        'saml2.want_assertions_signed' => 'SamlAdversarialCompletionTest::testAnUnsignedAssertionPassesOnlyThroughTheResponsesSignature:'
            . ' either value is valid, and off still needs the response\'s trusted signature',
        'saml2.idp_initiated' => 'SamlReinitiationTest::testEverySolicitedRuleStillHolds, ::testASecondPostOfTheSameResponseIsReplayed:'
            . ' either value is valid, and on re-initiates an unsolicited response through every check of a solicited one',
        'saml2.metadata_refresh' => 'MetadataExpiryTest::testADocumentAgesOutWithItsRefreshOff:'
            . ' either value is valid, and off still ages fetched metadata out at the stale limit',
        'oidc.trusted_audiences' => 'OidcAdversarialCallbackTest::testAWrongClaimIsRefusedThroughTheCallback (aud with a trusted, no azp;'
            . ' aud with an untrusted): a trusted audience only adds one beside the client id, and then `azp` is required',
        'oidc.metadata_refresh' => 'OidcSettingsTest::testTheRefreshSwitchIsABooleanWhateverTheFeatureSays,'
            . ' MetadataExpiryTest::testADocumentAgesOutWithItsRefreshOff: either value is valid, and off never means unlimited trust',
    ];

    /**
     * Every SAML setting is in the inventory, in the enum's order, and no
     * other.
     *
     * @return void
     */
    public function testEverySamlSettingIsAccountedFor(): void
    {
        self::assertSame(array_column(Saml2Setting::cases(), 'value'), array_keys(self::SAML));
    }

    /**
     * Every OIDC setting is in the inventory, in the enum's order, and no
     * other.
     *
     * @return void
     */
    public function testEveryOidcSettingIsAccountedFor(): void
    {
        self::assertSame(array_column(OidcSetting::cases(), 'value'), array_keys(self::OIDC));
    }

    /**
     * Rows of `[settings class, values, violation]`: a value that would weaken
     * a check below its clause's floor, and the violation that refuses it.
     *
     * @return iterable<string, array{0: class-string<\SineMacula\Laravel\Sso\Contracts\ProtocolSettings>, 1: array<string, mixed>, 2: array{0: string, 1: string}}>
     */
    public static function provideWeakeningValues(): iterable
    {
        yield 'a transient name id' => [Saml2Settings::class, ['name_id_format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'], ['name_id_format', 'not_allowed']];
        yield 'a sha-1 signature' => [Saml2Settings::class, ['signature_algorithms' => ['http://www.w3.org/2000/09/xmldsig#rsa-sha1']], ['signature_algorithms.0', 'not_allowed']];
        yield 'no signature algorithm' => [Saml2Settings::class, ['signature_algorithms' => []], ['signature_algorithms', 'required']];
        yield 'rsa 1.5 key transport' => [
            Saml2Settings::class,
            ['encryption_algorithms' => ['http://www.w3.org/2001/04/xmlenc#rsa-1_5', 'http://www.w3.org/2009/xmlenc11#aes128-gcm']],
            ['encryption_algorithms.0', 'not_allowed'],
        ];
        yield 'the none algorithm' => [OidcSettings::class, ['id_token_algorithms' => ['none']], ['id_token_algorithms.0', 'not_allowed']];
        yield 'an hmac algorithm' => [OidcSettings::class, ['id_token_algorithms' => ['HS256']], ['id_token_algorithms.0', 'not_allowed']];
        yield 'no id token algorithm' => [OidcSettings::class, ['id_token_algorithms' => []], ['id_token_algorithms', 'required']];
        yield 'no client authentication' => [OidcSettings::class, ['client_authentication' => 'none'], ['client_authentication', 'not_allowed']];
        yield 'an hmac client assertion' => [OidcSettings::class, ['client_assertion_algorithm' => 'HS256'], ['client_assertion_algorithm', 'not_allowed']];
        yield 'a flow parameter' => [OidcSettings::class, ['extra_parameters' => ['nonce' => 'fixed']], ['extra_parameters.nonce', 'reserved']];
    }

    /**
     * A `chooses` setting refuses the value that would weaken its check, so no
     * setting turns a check off.
     *
     * @param  class-string<\SineMacula\Laravel\Sso\Contracts\ProtocolSettings>  $class
     * @param  array<string, mixed>  $values
     * @param  array{0: string, 1: string}  $violation
     * @return void
     */
    #[DataProvider('provideWeakeningValues')]
    public function testAWeakeningValueIsRefused(string $class, array $values, array $violation): void
    {
        self::assertContains($violation, self::violationsOf($class::fromArray($values)));
    }

    /**
     * Every `chooses` setting is placed exactly once, by a weakening row or
     * another test, and nothing else is placed.
     *
     * @return void
     */
    public function testEveryChoosingSettingRefusesItsWeakeningValueOrIsProvenElsewhere(): void
    {
        $choosing = [
            ...array_map(static fn (string $name): string => 'saml2.' . $name, array_keys(self::SAML, 'chooses', true)),
            ...array_map(static fn (string $name): string => 'oidc.' . $name, array_keys(self::OIDC, 'chooses', true)),
        ];

        $refused = [];

        foreach (self::provideWeakeningValues() as [$class, $values]) {
            foreach (array_keys($values) as $name) {
                $refused[] = ($class === Saml2Settings::class ? 'saml2.' : 'oidc.') . $name;
            }
        }

        $placed = [...array_values(array_unique($refused)), ...array_keys(self::PROVEN_ELSEWHERE)];

        sort($choosing);
        sort($placed);

        self::assertSame($choosing, $placed);
    }

    /**
     * The violations of the settings, as `[setting, code]` pairs.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\ProtocolSettings  $settings
     * @return list<array{0: string, 1: string}>
     */
    private static function violationsOf(ProtocolSettings $settings): array
    {
        return array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $settings->violations());
    }
}
