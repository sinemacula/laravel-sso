<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use Tests\TestCase;

/**
 * Feature tests for the SAML settings (SSO-2.3, SSO-5.8, SSO-6.7 to SSO-6.9):
 * their defaults, every rule with its code and path, the settings that need a
 * feature switched on, completeness, and the classification they take from
 * `Saml2Setting`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Saml2Settings::class)]
#[CoversClass(SettingRules::class)]
final class Saml2SettingsTest extends TestCase
{
    /** @var string An identity provider's entity id. */
    private const string ENTITY_ID = 'https://idp.example.com/entity';

    /** @var string An identity provider's single sign-on URL. */
    private const string SSO_URL = 'https://idp.example.com/sso';

    /** @var string The SHA-256 RSA signature algorithm. */
    private const string RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    /** @var string RSA-PSS with SHA-256, which the library does not verify. */
    private const string RSA_PSS = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';

    /** @var string The RSA-OAEP key transport algorithm. */
    private const string RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';

    /** @var string The AES-128-GCM data encryption algorithm. */
    private const string AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';

    /** @var string The AES-256-GCM data encryption algorithm, which the library cannot decrypt. */
    private const string AES256_GCM = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';

    /**
     * Nothing given stores every default, in the order the settings are named.
     *
     * @return void
     */
    public function testAppliesTheDefaults(): void
    {
        $settings = Saml2Settings::fromArray([]);

        self::assertSame([
            'sso_binding'                  => 'http_redirect',
            'subject_source'               => 'name_id',
            'name_id_format'               => 'persistent',
            'sign_authn_requests'          => false,
            'want_assertions_signed'       => true,
            'require_encrypted_assertions' => false,
            'signature_algorithms'         => Saml2Settings::SIGNATURE_ALGORITHMS,
            'encryption_algorithms'        => [...Saml2Settings::KEY_TRANSPORT_ALGORITHMS, ...Saml2Settings::DATA_ENCRYPTION_ALGORITHMS],
            'force_authn'                  => false,
            'requested_authn_context'      => [],
            'idp_initiated'                => false,
        ], $settings->toArray());

        self::assertSame([], $settings->violations());
        self::assertSame([
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
        ], Saml2Settings::SIGNATURE_ALGORITHMS);
        self::assertSame(['http://www.w3.org/2009/xmlenc11#aes128-gcm', 'http://www.w3.org/2009/xmlenc11#aes192-gcm'], Saml2Settings::DATA_ENCRYPTION_ALGORITHMS);
    }

    /**
     * What is given is kept as given, in the order the settings are named, a
     * `null` is a setting not given, and a name the protocol does not have is
     * never stored.
     *
     * @return void
     */
    public function testStoresWhatIsGivenInTheOrderTheSettingsAreNamed(): void
    {
        $stored = Saml2Settings::fromArray([
            'force_authn'    => true,
            'sso_url'        => self::SSO_URL,
            'sso_binding'    => null,
            'idp_entity_id'  => self::ENTITY_ID,
            'name_id_format' => 'email',
            'unknown'        => 'value',
        ])->toArray();

        self::assertSame(['idp_entity_id', 'sso_url', 'sso_binding', 'subject_source', 'name_id_format'], array_slice(array_keys($stored), 0, 5));
        self::assertSame(self::ENTITY_ID, $stored['idp_entity_id']);
        self::assertSame(self::SSO_URL, $stored['sso_url']);
        self::assertSame('http_redirect', $stored['sso_binding']);
        self::assertSame('email', $stored['name_id_format']);
        self::assertTrue($stored['force_authn']);
        self::assertArrayNotHasKey('unknown', $stored);
        self::assertArrayNotHasKey('subject_attribute', $stored);
    }

    /**
     * Every value the rules allow is accepted, with both features on.
     *
     * @return void
     */
    public function testAcceptsEveryAllowedValue(): void
    {
        config()->set('sso.features.encrypted_assertions', true);
        config()->set('sso.features.idp_initiated', true);
        config()->set('sso.features.metadata_refresh', true);

        $settings = Saml2Settings::fromArray([
            'idp_entity_id'                  => 'urn:example:idp',
            'sso_url'                        => 'https://idp.example.com:8443/sso?tenant=1',
            'sso_binding'                    => 'http_post',
            'subject_source'                 => 'attribute',
            'subject_attribute'              => 'employee id',
            'name_id_format'                 => 'unspecified',
            'sign_authn_requests'            => true,
            'want_assertions_signed'         => false,
            'require_encrypted_assertions'   => true,
            'signature_algorithms'           => Saml2Settings::SIGNATURE_ALGORITHMS,
            'encryption_algorithms'          => [...Saml2Settings::KEY_TRANSPORT_ALGORITHMS, ...Saml2Settings::DATA_ENCRYPTION_ALGORITHMS, ...Saml2Settings::CBC_ALGORITHMS],
            'force_authn'                    => true,
            'requested_authn_context'        => array_fill(0, Saml2Settings::MAX_AUTHN_CONTEXTS, 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'),
            'max_authentication_age_seconds' => 3600,
            'idp_initiated'                  => true,
            'idp_initiated_start_url'        => 'https://app.example.com/sso/start',
            'metadata_url'                   => 'https://idp.example.com/metadata.xml',
            'metadata_refresh'               => true,
        ]);

        self::assertSame([], $settings->violations());
        self::assertTrue($settings->isComplete());

        foreach (['http://idp.example.com/entity', 'HTTPS://IDP.EXAMPLE.COM/', 'urn:oid:1.2.3'] as $entityId) {
            self::assertSame([], Saml2Settings::fromArray(['idp_entity_id' => $entityId])->violations(), $entityId);
        }

        foreach (['persistent', 'email', 'unspecified'] as $format) {
            self::assertSame([], Saml2Settings::fromArray(['name_id_format' => $format])->violations(), $format);
        }

        self::assertSame([], Saml2Settings::fromArray(['sso_url' => 'https://[2001:db8::1]/sso'])->violations());
        self::assertSame([], Saml2Settings::fromArray(['idp_entity_id' => 'urn:x:' . str_repeat('a', 1018)])->violations());

        foreach ([Saml2Settings::MIN_AUTHENTICATION_AGE_SECONDS, Saml2Settings::MAX_AUTHENTICATION_AGE_SECONDS] as $age) {
            self::assertSame([], Saml2Settings::fromArray(['max_authentication_age_seconds' => $age])->violations(), (string) $age);
        }
    }

    /**
     * Rows of `[values, violations]`: settings given, and each violation they
     * report as `[setting, code]`, in order.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: list<array{0: string, 1: string}>}>
     */
    public static function provideViolations(): iterable
    {
        $overlongUrl = 'https://idp.example.com/' . str_repeat('a', SettingRules::MAX_URL_LENGTH - 23);

        yield from [
            'an entity id that is not a string' => [['idp_entity_id' => 5], [['idp_entity_id', 'invalid_type']]],
            'an empty entity id'                => [['idp_entity_id' => ''], [['idp_entity_id', 'required']]],
            'an overlong entity id'             => [['idp_entity_id' => 'urn:x:' . str_repeat('a', 1019)], [['idp_entity_id', 'too_long']]],
            'an entity id with a space'         => [['idp_entity_id' => 'https://idp.example.com/an entity'], [['idp_entity_id', 'invalid_format']]],
            'an entity id with a control'       => [['idp_entity_id' => "urn:x:\x01y"], [['idp_entity_id', 'invalid_format']]],
            'a relative entity id'              => [['idp_entity_id' => 'idp.example.com'], [['idp_entity_id', 'invalid_format']]],
            'an entity id of another scheme'    => [['idp_entity_id' => 'ftp://idp.example.com'], [['idp_entity_id', 'invalid_format']]],
            'an entity id with no host'         => [['idp_entity_id' => 'https://'], [['idp_entity_id', 'invalid_format']]],
            'a bare urn'                        => [['idp_entity_id' => 'urn:example'], [['idp_entity_id', 'invalid_format']]],
            'a url that is not a string'        => [['sso_url' => ['https://idp.example.com']], [['sso_url', 'invalid_type']]],
            'an empty url'                      => [['sso_url' => ''], [['sso_url', 'required']]],
            'an http url'                       => [['sso_url' => 'http://idp.example.com/sso'], [['sso_url', 'not_https']]],
            'a url of another scheme'           => [['sso_url' => 'ftp://idp.example.com/sso'], [['sso_url', 'not_https']]],
            'a url with a fragment'             => [['sso_url' => 'https://idp.example.com/sso#top'], [['sso_url', 'invalid_format']]],
            'a url with userinfo'               => [['sso_url' => 'https://user:pass@idp.example.com/sso'], [['sso_url', 'invalid_format']]],
            'a url with no scheme'              => [['sso_url' => 'idp.example.com/sso'], [['sso_url', 'invalid_format']]],
            'a url with no host'                => [['sso_url' => 'https:/sso'], [['sso_url', 'invalid_format']]],
            'a url with a malformed host'       => [['sso_url' => 'https://-idp.example.com/sso'], [['sso_url', 'invalid_format']]],
            'a url with a space'                => [['sso_url' => 'https://idp.example.com/s so'], [['sso_url', 'invalid_format']]],
            'an overlong url'                   => [['sso_url' => $overlongUrl], [['sso_url', 'too_long']]],
            'a binding not allowed'             => [['sso_binding' => 'soap'], [['sso_binding', 'not_allowed']]],
            'a binding that is not a string'    => [['sso_binding' => 1], [['sso_binding', 'invalid_type']]],
            'a subject source not allowed'      => [['subject_source' => 'email'], [['subject_source', 'not_allowed']]],
            'an attribute source with no name'  => [['subject_source' => 'attribute'], [['subject_attribute', 'required']]],
            'an attribute with the name id'     => [['subject_attribute' => 'uid'], [['subject_attribute', 'unsupported']]],
            'an attribute with the explicit id' => [['subject_source' => 'name_id', 'subject_attribute' => 'uid'], [['subject_attribute', 'unsupported']]],
            'an empty attribute'                => [['subject_source' => 'attribute', 'subject_attribute' => ''], [['subject_attribute', 'required']]],
            'an attribute with a control'       => [['subject_source' => 'attribute', 'subject_attribute' => "u\nid"], [['subject_attribute', 'invalid_format']]],
            'an overlong attribute'             => [['subject_source' => 'attribute', 'subject_attribute' => str_repeat('a', 1025)], [['subject_attribute', 'too_long']]],
            'a transient name id'               => [['name_id_format' => 'transient'], [['name_id_format', 'not_allowed']]],
            'a name id format by its urn'       => [['name_id_format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'], [['name_id_format', 'not_allowed']]],
            'a string for signing requests'     => [['sign_authn_requests' => 'true'], [['sign_authn_requests', 'invalid_type']]],
            'a number for signed assertions'    => [['want_assertions_signed' => 1], [['want_assertions_signed', 'invalid_type']]],
            'a string for encrypted assertions' => [['require_encrypted_assertions' => 'false'], [['require_encrypted_assertions', 'invalid_type']]],
            'a number for forcing authn'        => [['force_authn' => 0], [['force_authn', 'invalid_type']]],
            'a string for idp-initiated'        => [['idp_initiated' => 'yes'], [['idp_initiated', 'invalid_type']]],
            'no signature algorithm'            => [['signature_algorithms' => []], [['signature_algorithms', 'required']]],
            'a signature algorithm string'      => [['signature_algorithms' => self::RSA_SHA256], [['signature_algorithms', 'invalid_type']]],
            'signature algorithms as a map'     => [['signature_algorithms' => ['rsa' => self::RSA_SHA256]], [['signature_algorithms', 'invalid_type']]],
            'sha-1'                             => [
                ['signature_algorithms' => [self::RSA_SHA256, 'http://www.w3.org/2000/09/xmldsig#rsa-sha1']],
                [['signature_algorithms.1', 'not_allowed']],
            ],
            'a signature algorithm twice'  => [['signature_algorithms' => [self::RSA_SHA256, self::RSA_SHA256]], [['signature_algorithms.1', 'duplicate']]],
            'a signature algorithm number' => [['signature_algorithms' => [256]], [['signature_algorithms.0', 'invalid_type']]],
            'no encryption algorithm'      => [['encryption_algorithms' => []], [['encryption_algorithms', 'required']]],
            'rsa 1.5'                      => [
                ['encryption_algorithms' => [self::RSA_OAEP, 'http://www.w3.org/2001/04/xmlenc#rsa-1_5', self::AES128_GCM]],
                [['encryption_algorithms.1', 'not_allowed']],
            ],
            'an encryption algorithm twice' => [['encryption_algorithms' => [self::RSA_OAEP, self::AES128_GCM, self::AES128_GCM]], [['encryption_algorithms.2', 'duplicate']]],
            'no key transport'              => [['encryption_algorithms' => [self::AES128_GCM]], [['encryption_algorithms', 'required']]],
            'aes-256-gcm'                   => [['encryption_algorithms' => [self::RSA_OAEP, self::AES256_GCM]], [['encryption_algorithms.1', 'not_allowed']]],
            'ecdsa'                         => [['signature_algorithms' => ['http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256']], [['signature_algorithms.0', 'not_allowed']]],
            'rsa-pss'                       => [['signature_algorithms' => [self::RSA_PSS]], [['signature_algorithms.0', 'not_allowed']]],
            'an age as a string'            => [['max_authentication_age_seconds' => '3600'], [['max_authentication_age_seconds', 'invalid_type']]],
            'an age one under the least'    => [['max_authentication_age_seconds' => 59], [['max_authentication_age_seconds', 'not_allowed']]],
            'an age one over the most'      => [['max_authentication_age_seconds' => 604801], [['max_authentication_age_seconds', 'not_allowed']]],
            'an http metadata url'          => [['metadata_url' => 'http://idp.example.com/metadata'], [['metadata_url', 'not_https']]],
            'a string for metadata refresh' => [['metadata_refresh' => 'yes'], [['metadata_refresh', 'invalid_type']]],
            'no data encryption'            => [['encryption_algorithms' => [self::RSA_OAEP]], [['encryption_algorithms', 'required']]],
            'too many context classes'      => [['requested_authn_context' => array_fill(0, 11, 'urn:x:y')], [['requested_authn_context', 'too_many']]],
            'a context class string'        => [['requested_authn_context' => 'urn:x:y'], [['requested_authn_context', 'invalid_type']]],
            'a context class with a space'  => [['requested_authn_context' => ['urn:x:y', 'urn x']], [['requested_authn_context.1', 'invalid_format']]],
            'a context class number'        => [['requested_authn_context' => [1]], [['requested_authn_context.0', 'invalid_type']]],
            'an overlong context class'     => [['requested_authn_context' => [str_repeat('a', 1025)]], [['requested_authn_context.0', 'too_long']]],
            'an http start url'             => [['idp_initiated_start_url' => 'http://app.example.com/start'], [['idp_initiated_start_url', 'not_https']]],
            'an unknown setting'            => [['client_id' => 'abc'], [['client_id', 'unknown']]],
            'an unnamed setting'            => [['' => 'abc'], [['settings', 'unknown']]],
            'a numbered setting'            => [['abc'], [['0', 'unknown']]],
            'a known setting, then unknown' => [['sso_url' => 'https://idp.example.com/sso', 'client_id' => 'abc'], [['client_id', 'unknown']]],
            'context classes as a map'      => [['requested_authn_context' => ['a' => 'urn:x:y']], [['requested_authn_context', 'invalid_type']]],
            'two context classes refused'   => [['requested_authn_context' => [1, '']], [['requested_authn_context.0', 'invalid_type'], ['requested_authn_context.1', 'required']]],
            'two encryption algorithms'     => [['encryption_algorithms' => ['x', 'y']], [['encryption_algorithms.0', 'not_allowed'], ['encryption_algorithms.1', 'not_allowed']]],
            'several, in the order named'   => [
                ['unknown' => true, 'name_id_format' => 'transient', 'sso_url' => 'http://idp.example.com', 'idp_entity_id' => ''],
                [['idp_entity_id', 'required'], ['sso_url', 'not_https'], ['name_id_format', 'not_allowed'], ['unknown', 'unknown']],
            ],
        ];
    }

    /**
     * Each rule reports its code at its setting's path, never the value.
     *
     * @param  array<array-key, mixed>  $values
     * @param  list<array{0: string, 1: string}>  $expected
     * @return void
     */
    #[DataProvider('provideViolations')]
    public function testReportsEachViolationAtItsSetting(array $values, array $expected): void
    {
        $settings = Saml2Settings::fromArray($values);

        self::assertSame($expected, self::violationsOf($settings));
        self::assertFalse($settings->isComplete());
    }

    /**
     * Encrypted assertions may be required only while the feature is on.
     *
     * @return void
     */
    public function testRequiresTheFeatureForEncryptedAssertions(): void
    {
        $settings = Saml2Settings::fromArray(['require_encrypted_assertions' => true]);

        self::assertSame([['require_encrypted_assertions', 'unsupported']], self::violationsOf($settings));
        self::assertSame([], self::violationsOf(Saml2Settings::fromArray(['require_encrypted_assertions' => false])));

        config()->set('sso.features.encrypted_assertions', true);

        self::assertSame([], self::violationsOf($settings));
    }

    /**
     * IdP-initiated sign-in may be on only while the feature is, and then needs
     * its start URL.
     *
     * @return void
     */
    public function testRequiresTheFeatureAndAStartUrlForIdpInitiatedSignIn(): void
    {
        $withoutUrl = Saml2Settings::fromArray(['idp_initiated' => true]);
        $withUrl    = Saml2Settings::fromArray(['idp_initiated' => true, 'idp_initiated_start_url' => 'https://app.example.com/start']);

        self::assertSame([['idp_initiated', 'unsupported'], ['idp_initiated_start_url', 'required']], self::violationsOf($withoutUrl));
        self::assertSame([['idp_initiated', 'unsupported']], self::violationsOf($withUrl));

        config()->set('sso.features.idp_initiated', true);

        self::assertSame([['idp_initiated_start_url', 'required']], self::violationsOf($withoutUrl));
        self::assertSame([], self::violationsOf($withUrl));
        self::assertSame([], self::violationsOf(Saml2Settings::fromArray(['idp_initiated_start_url' => 'https://app.example.com/start'])));
    }

    /**
     * An explicit metadata refresh needs the metadata URL, whatever the feature
     * says, since the feature stops only the schedule; the URL alone is
     * allowed.
     *
     * @return void
     */
    public function testAnExplicitMetadataRefreshNeedsAUrlWhateverTheFeatureSays(): void
    {
        $withoutUrl = Saml2Settings::fromArray(['metadata_refresh' => true]);
        $withUrl    = Saml2Settings::fromArray(['metadata_refresh' => true, 'metadata_url' => 'https://idp.example.com/metadata']);

        foreach ([false, true] as $feature) {
            config()->set('sso.features.metadata_refresh', $feature);

            self::assertSame([['metadata_url', 'required']], self::violationsOf($withoutUrl));
            self::assertSame([], self::violationsOf($withUrl));
            self::assertSame([], self::violationsOf(Saml2Settings::fromArray(['metadata_url' => 'https://idp.example.com/metadata', 'metadata_refresh' => false])));
            self::assertSame([], self::violationsOf(Saml2Settings::fromArray(['metadata_url' => 'https://idp.example.com/metadata'])));
            self::assertSame([], self::violationsOf(Saml2Settings::fromArray([])));

            $malformed = Saml2Settings::fromArray(['metadata_url' => 'https://idp.example.com/metadata', 'metadata_refresh' => 1]);

            self::assertSame([['metadata_refresh', 'invalid_type']], self::violationsOf($malformed));
        }
    }

    /**
     * The refresh switch is stored only when it is given, so a connection
     * follows its URL until an administrator says otherwise.
     *
     * @return void
     */
    public function testTheMetadataRefreshIsStoredOnlyWhenGiven(): void
    {
        self::assertArrayNotHasKey('metadata_refresh', Saml2Settings::fromArray(['metadata_url' => 'https://idp.example.com/metadata'])->toArray());
        self::assertFalse(Saml2Settings::fromArray(['metadata_refresh' => false])->toArray()['metadata_refresh']);
    }

    /**
     * A malformed feature switch fails closed rather than allowing the setting.
     *
     * @return void
     */
    public function testAMalformedFeatureSwitchFailsClosed(): void
    {
        config()->set('sso.features.encrypted_assertions', 'perhaps');

        $this->expectException(\InvalidArgumentException::class);

        Saml2Settings::fromArray(['require_encrypted_assertions' => true])->violations();
    }

    /**
     * Complete once valid and naming the entity id and single sign-on URL.
     *
     * @return void
     */
    public function testIsCompleteWithTheEntityIdAndSingleSignOnUrl(): void
    {
        self::assertTrue(Saml2Settings::fromArray(['idp_entity_id' => self::ENTITY_ID, 'sso_url' => self::SSO_URL])->isComplete());
        self::assertFalse(Saml2Settings::fromArray([])->isComplete());
        self::assertFalse(Saml2Settings::fromArray(['idp_entity_id' => self::ENTITY_ID])->isComplete());
        self::assertFalse(Saml2Settings::fromArray(['sso_url' => self::SSO_URL])->isComplete());
        self::assertFalse(Saml2Settings::fromArray(['idp_entity_id' => self::ENTITY_ID, 'sso_url' => self::SSO_URL, 'force_authn' => 'yes'])->isComplete());
    }

    /**
     * The classification is `Saml2Setting`'s: each setting's operation, the
     * subject settings, and no secret.
     *
     * @return void
     */
    public function testTakesItsClassificationFromTheSettingEnum(): void
    {
        foreach (Saml2Setting::cases() as $setting) {
            self::assertSame($setting->freshness(), Saml2Settings::freshnessFor($setting->value), $setting->value);
        }

        self::assertNull(Saml2Settings::freshnessFor('client_secret'));
        self::assertSame(Saml2Setting::subjectNames(), Saml2Settings::subjectNames());
        self::assertSame(['idp_entity_id', 'subject_source', 'subject_attribute', 'name_id_format'], Saml2Settings::subjectNames());
        self::assertSame(['idp_entity_id'], Saml2Settings::issuerNames());
        self::assertSame([], Saml2Settings::secretNames());
    }

    /**
     * Each violation as `[setting, code]`.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings  $settings
     * @return list<array{0: string, 1: string}>
     */
    private static function violationsOf(Saml2Settings $settings): array
    {
        return array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $settings->violations());
    }
}
