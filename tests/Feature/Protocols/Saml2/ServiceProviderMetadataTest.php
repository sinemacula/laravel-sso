<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\ServiceProviderMetadata;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for a SAML connection's service provider metadata (SSO-5.9),
 * through the driver: every element and attribute, pinned as the whole
 * document; the document valid against the SAML 2.0 metadata schema through the
 * package's hardened parser; the current and next certificates published during
 * a rotation and only the current one once it ends; the encryption methods
 * following the allow-list, never AES-256-GCM or RSA 1.5; the flags and NameID
 * format following the settings; a connection with no identity provider
 * settings still described; another connection's keys, and a key with no
 * certificate, left out; no private key or secret anywhere; and the same bytes
 * for the same state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ServiceProviderMetadata::class)]
#[CoversClass(Saml2Driver::class)]
final class ServiceProviderMetadataTest extends TestCase
{
    use UsesConnections;

    /** @var string The base URL the endpoints are built from. */
    private const string BASE_URL = 'https://api.example.com';

    /** @var array<string, string> Complete identity provider settings. */
    private const array SETTINGS = ['idp_entity_id' => 'https://idp.example.com/entity', 'sso_url' => 'https://idp.example.com/sso'];

    /** @var string The persistent NameID format. */
    private const string PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    /** @var string RSA-OAEP key transport (XML Encryption 1.1). */
    private const string RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';

    /** @var string RSA-OAEP key transport with MGF1 over SHA-1. */
    private const string RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

    /** @var string AES-128-GCM. */
    private const string AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';

    /** @var string AES-192-GCM. */
    private const string AES192_GCM = 'http://www.w3.org/2009/xmlenc11#aes192-gcm';

    /** @var string AES-256-GCM, which the library cannot decrypt until saml2 v7. */
    private const string AES256_GCM = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';

    /** @var string AES-128-CBC. */
    private const string AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';

    /** @var string RSA 1.5 key transport, never allowed. */
    private const string RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';

    /** @var list<string> The encryption methods a connection allows by default, data algorithms first. */
    private const array DEFAULT_METHODS = [self::AES128_GCM, self::AES192_GCM, self::RSA_OAEP, self::RSA_OAEP_MGF1P];

    /** @var string A private key's ciphertext as a row holds it. */
    private const string CIPHERTEXT = 'the-stored-private-key-ciphertext';

    /**
     * Bind a fixed clock and a fresh caller, configure the endpoints, switch
     * SAML on, and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, new RecordingFreshness);

        config()->set('sso.features.saml2', true);
        config()->set('sso.endpoints.base_url', self::BASE_URL);

        $this->createConnectionTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * The metadata is the whole document expected, as
     * `application/samlmetadata+xml`, valid against the SAML 2.0 metadata
     * schema; another connection's key is not in it.
     *
     * @return void
     */
    public function testDescribesTheServiceProviderAsSchemaValidMetadata(): void
    {
        $connection = $this->saml(self::SETTINGS);
        $other      = $this->saml(self::SETTINGS);

        $this->key($connection, KeyUse::SP_SIGNING, KeyState::CURRENT, Certificates::distinct(0));
        $this->key($connection, KeyUse::SP_ENCRYPTION, KeyState::CURRENT, Certificates::distinct(1));
        $this->key($other, KeyUse::SP_SIGNING, KeyState::CURRENT, Certificates::distinct(2));

        $description = $this->describe($connection);

        self::assertTrue($description->isAvailable());
        self::assertNull($description->reason);
        self::assertSame('application/samlmetadata+xml', $description->contentType);
        self::assertSame('application/samlmetadata+xml', ServiceProviderMetadata::CONTENT_TYPE);
        self::assertSame(self::expected($connection, [Certificates::distinct(0)], [Certificates::distinct(1)]), $description->body);
        self::assertStringNotContainsString(self::body(Certificates::distinct(2)), $description->body);

        $document = self::parsed($description);

        self::assertSame('EntityDescriptor', $document->documentElement?->localName);
    }

    /**
     * During a rotation the current and next certificates of each use are
     * published, the current first; once the next is made current only it is
     * published, and so it stays after the old key is retired.
     *
     * @return void
     */
    public function testPublishesTheCurrentAndNextCertificatesDuringARotationAndOnlyTheCurrentAfter(): void
    {
        $connection = $this->saml(self::SETTINGS);

        $signing    = $this->addKey($connection, KeyUse::SP_SIGNING);
        $encryption = $this->addKey($connection, KeyUse::SP_ENCRYPTION);

        self::assertSame(KeyState::CURRENT, $signing->state);
        self::assertSame(self::expected($connection, [self::certificateOf($signing)], [self::certificateOf($encryption)]), $this->describe($connection)->body);

        $nextSigning    = $this->addKey($connection, KeyUse::SP_SIGNING);
        $nextEncryption = $this->addKey($connection, KeyUse::SP_ENCRYPTION);

        self::assertSame(KeyState::NEXT, $nextSigning->state);

        $during           = $this->describe($connection);
        $duringSigning    = [self::certificateOf($signing), self::certificateOf($nextSigning)];
        $duringEncryption = [self::certificateOf($encryption), self::certificateOf($nextEncryption)];

        self::assertSame(self::expected($connection, $duringSigning, $duringEncryption), $during->body);
        self::assertSame(['signing', 'signing', 'encryption', 'encryption'], self::keyUses(self::parsed($during)));

        $this->keyService()->makeCurrent('tenant-1', $connection->id, $nextSigning->id);
        $this->keyService()->makeCurrent('tenant-1', $connection->id, $nextEncryption->id);

        $after = self::expected($connection, [self::certificateOf($nextSigning)], [self::certificateOf($nextEncryption)]);

        self::assertSame($after, $this->describe($connection)->body);

        $this->keyService()->retire('tenant-1', $connection->id, $signing->id);
        $this->keyService()->retire('tenant-1', $connection->id, $encryption->id);

        $retired = $this->describe($connection);

        self::assertSame($after, $retired->body);
        self::assertSame(['signing', 'encryption'], self::keyUses(self::parsed($retired)));

        $this->assertHoldsNoPrivateKey($connection, $retired->body);
    }

    /**
     * Rows of `[encryption algorithms, methods]`: the algorithms a connection
     * stores and the encryption methods its metadata advertises, data
     * algorithms first, each group in the order stored.
     *
     * @return iterable<string, array{0: ?list<string>, 1: list<string>}>
     */
    public static function provideEncryptionAlgorithms(): iterable
    {
        yield from [
            'the default' => [null, self::DEFAULT_METHODS],
            'one of each' => [[self::RSA_OAEP, self::AES192_GCM], [self::AES192_GCM, self::RSA_OAEP]],
            'reordered'   => [
                [self::RSA_OAEP_MGF1P, self::RSA_OAEP, self::AES192_GCM, self::AES128_GCM],
                [self::AES192_GCM, self::AES128_GCM, self::RSA_OAEP_MGF1P, self::RSA_OAEP],
            ],
            'AES-CBC listed'              => [[self::RSA_OAEP, self::AES128_CBC, self::AES128_GCM], [self::AES128_CBC, self::AES128_GCM, self::RSA_OAEP]],
            'stored but never advertised' => [[self::RSA_1_5, self::RSA_OAEP, self::AES256_GCM, self::AES128_GCM], [self::AES128_GCM, self::RSA_OAEP]],
        ];
    }

    /**
     * Each encryption certificate carries an encryption method for each
     * algorithm the connection allows, and never AES-256-GCM or RSA 1.5.
     *
     * @param  ?list<string>  $algorithms
     * @param  list<string>  $methods
     * @return void
     */
    #[DataProvider('provideEncryptionAlgorithms')]
    public function testTheEncryptionMethodsFollowTheAllowList(?array $algorithms, array $methods): void
    {
        $settings   = $algorithms === null ? self::SETTINGS : [...self::SETTINGS, 'encryption_algorithms' => $algorithms];
        $connection = $this->saml($settings);

        $this->key($connection, KeyUse::SP_SIGNING, KeyState::CURRENT, Certificates::distinct(0));
        $this->key($connection, KeyUse::SP_ENCRYPTION, KeyState::CURRENT, Certificates::distinct(1));
        $this->key($connection, KeyUse::SP_ENCRYPTION, KeyState::NEXT, Certificates::distinct(2));

        $description = $this->describe($connection);
        $xpath       = new \DOMXPath(self::parsed($description));
        $expected    = self::expected($connection, [Certificates::distinct(0)], [Certificates::distinct(1), Certificates::distinct(2)], ['methods' => $methods]);

        self::assertSame($expected, $description->body);
        self::assertSame([...$methods, ...$methods], self::values($xpath, '//md:KeyDescriptor[@use="encryption"]/md:EncryptionMethod/@Algorithm'));
        self::assertSame([], self::values($xpath, '//md:KeyDescriptor[@use="signing"]/md:EncryptionMethod/@Algorithm'));
        self::assertStringNotContainsString(self::AES256_GCM, $description->body);
        self::assertStringNotContainsString(self::RSA_1_5, $description->body);
    }

    /**
     * Rows of `[settings, AuthnRequestsSigned, WantAssertionsSigned]`.
     *
     * @return iterable<string, array{0: array<string, bool>, 1: string, 2: string}>
     */
    public static function provideFlags(): iterable
    {
        yield from [
            'the defaults'           => [[], 'false', 'true'],
            'signed, wanted'         => [['sign_authn_requests' => true, 'want_assertions_signed' => true], 'true', 'true'],
            'signed, not wanted'     => [['sign_authn_requests' => true, 'want_assertions_signed' => false], 'true', 'false'],
            'not signed, wanted'     => [['sign_authn_requests' => false, 'want_assertions_signed' => true], 'false', 'true'],
            'not signed, not wanted' => [['sign_authn_requests' => false, 'want_assertions_signed' => false], 'false', 'false'],
        ];
    }

    /**
     * `AuthnRequestsSigned` and `WantAssertionsSigned` follow the settings.
     *
     * @param  array<string, bool>  $settings
     * @param  string  $signed
     * @param  string  $wanted
     * @return void
     */
    #[DataProvider('provideFlags')]
    public function testTheFlagsFollowTheSettings(array $settings, string $signed, string $wanted): void
    {
        $connection  = $this->saml([...self::SETTINGS, ...$settings]);
        $description = $this->describe($connection);
        $xpath       = new \DOMXPath(self::parsed($description));

        self::assertSame(self::expected($connection, [], [], ['signed' => $signed, 'wanted' => $wanted]), $description->body);
        self::assertSame([$signed], self::values($xpath, '//md:SPSSODescriptor/@AuthnRequestsSigned'));
        self::assertSame([$wanted], self::values($xpath, '//md:SPSSODescriptor/@WantAssertionsSigned'));
    }

    /**
     * Rows of `[setting, NameID format]`.
     *
     * @return iterable<string, array{0: ?string, 1: string}>
     */
    public static function provideNameIdFormats(): iterable
    {
        yield from [
            'the default' => [null, self::PERSISTENT],
            'persistent'  => ['persistent', self::PERSISTENT],
            'email'       => ['email', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
            'unspecified' => ['unspecified', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'],
        ];
    }

    /**
     * The one NameID format is the connection's.
     *
     * @param  ?string  $setting
     * @param  string  $format
     * @return void
     */
    #[DataProvider('provideNameIdFormats')]
    public function testTheNameIdFormatFollowsTheSettings(?string $setting, string $format): void
    {
        $connection  = $this->saml($setting === null ? self::SETTINGS : [...self::SETTINGS, 'name_id_format' => $setting]);
        $description = $this->describe($connection);

        self::assertSame(self::expected($connection, [], [], ['format' => $format]), $description->body);
        self::assertSame([$format], self::values(new \DOMXPath(self::parsed($description)), '//md:SPSSODescriptor/md:NameIDFormat'));
    }

    /**
     * A connection with no identity provider settings and no keys, disabled, is
     * still described: its service provider side, with no key descriptor.
     *
     * @return void
     */
    public function testAConnectionWithNoIdentityProviderSettingsIsStillDescribed(): void
    {
        $connection  = $this->makeConnection(['protocol' => 'saml2', 'enabled' => false, 'settings' => []]);
        $description = $this->describe($connection);
        $xpath       = new \DOMXPath(self::parsed($description));

        self::assertFalse(app(ProtocolManager::class)->isUsable($connection));
        self::assertTrue($description->isAvailable());
        self::assertSame(self::expected($connection, [], []), $description->body);
        self::assertSame([], self::values($xpath, '//md:KeyDescriptor/@use'));
        self::assertSame([self::BASE_URL . '/auth/sso/connections/' . $connection->id . '/assertions'], self::values($xpath, '//md:AssertionConsumerService/@Location'));
    }

    /**
     * A published key with no certificate, and a retiring key, are left out.
     *
     * @return void
     */
    public function testAKeyWithNoCertificateAndARetiringKeyAreLeftOut(): void
    {
        $connection = $this->saml(self::SETTINGS);

        $this->key($connection, KeyUse::SP_SIGNING, KeyState::CURRENT, Certificates::distinct(0), withCertificate: false);
        $this->key($connection, KeyUse::SP_SIGNING, KeyState::NEXT, Certificates::distinct(1));
        $this->key($connection, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, Certificates::distinct(2));
        $this->key($connection, KeyUse::SP_ENCRYPTION, KeyState::CURRENT, Certificates::distinct(3));

        self::assertCount(2, app(KeyRing::class)->published($connection->id, KeyUse::SP_SIGNING));
        self::assertSame(self::expected($connection, [Certificates::distinct(1)], [Certificates::distinct(3)]), $this->describe($connection)->body);
    }

    /**
     * No private key, no ciphertext of one and no PEM block is in the metadata,
     * whatever the rows hold.
     *
     * @return void
     */
    public function testHoldsNoPrivateKeyOrSecret(): void
    {
        $connection = $this->saml(self::SETTINGS);

        $this->key($connection, KeyUse::SP_SIGNING, KeyState::CURRENT, Certificates::distinct(0));
        $this->key($connection, KeyUse::SP_ENCRYPTION, KeyState::CURRENT, Certificates::distinct(1));

        $body = (string) $this->describe($connection)->body;

        self::assertStringNotContainsString('PRIVATE', $body);
        self::assertStringNotContainsString('-----', $body);
        self::assertStringNotContainsString(self::CIPHERTEXT, $body);
        self::assertStringNotContainsString('Signature', $body);
    }

    /**
     * The same connection, keys and endpoints always give the same bytes, from
     * the same driver and from another built afresh.
     *
     * @return void
     */
    public function testTheSameStateGivesTheSameBytes(): void
    {
        $connection = $this->saml([...self::SETTINGS, 'sign_authn_requests' => true]);

        $this->key($connection, KeyUse::SP_SIGNING, KeyState::CURRENT, Certificates::distinct(0));
        $this->key($connection, KeyUse::SP_SIGNING, KeyState::NEXT, Certificates::distinct(1));
        $this->key($connection, KeyUse::SP_ENCRYPTION, KeyState::CURRENT, Certificates::distinct(2));

        $first  = $this->describe($connection);
        $second = $this->describe($connection);
        $fresh  = app(ServiceProviderMetadata::class)->describe($connection->fresh() ?? $connection, Saml2Options::of($connection));

        self::assertSame($first->body, $second->body);
        self::assertSame($first->body, $fresh->body);
        self::assertEquals($first, $fresh);
    }

    /**
     * Fail unless no part of a private key of the connection, decrypted or as
     * stored, is in the body.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $body
     * @return void
     */
    private function assertHoldsNoPrivateKey(Connection $connection, string $body): void
    {
        self::assertStringNotContainsString('PRIVATE', $body);

        $rows = ConnectionKey::query()->where('connection_id', $connection->id)->get();

        self::assertCount(2, $rows);

        foreach ($rows as $row) {

            $stored  = $row->getRawOriginal('private_key');
            $private = app(KeyRing::class)->privateKey($connection->id, $row->id)->reveal();
            $lines   = array_filter(explode("\n", $private), static fn (string $line): bool => $line !== '' && !str_starts_with($line, '-----'));

            self::assertIsString($stored);
            self::assertNotSame('', $stored);
            self::assertStringNotContainsString($stored, $body);

            foreach ($lines as $line) {
                self::assertStringNotContainsString($line, $body);
            }
        }
    }

    /**
     * The connection's description, through the protocol manager's driver.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    private function describe(Connection $connection): ServiceProviderDescription
    {
        return app(ProtocolManager::class)->protocol(Saml2Driver::NAME)->describe($connection);
    }

    /**
     * Add a key of the use through the key service, as the first (current) or
     * the next.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private function addKey(Connection $connection, KeyUse $use): KeySummary
    {
        $key = $this->keyService()->addNext('tenant-1', $connection->id, $use, KeyType::RSA)->key;

        self::assertNotNull($key);

        return $key;
    }

    /**
     * The key service, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyService
     */
    private function keyService(): KeyService
    {
        return app(KeyService::class);
    }

    /**
     * A SAML connection of `tenant-1`, enabled, with the settings given.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(array $settings): Connection
    {
        return $this->makeConnection(['protocol' => 'saml2', 'enabled' => true, 'settings' => $settings]);
    }

    /**
     * Store one of the connection's own keys of the use and state with the
     * certificate given, or with only its public key.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  string  $certificate
     * @param  bool  $withCertificate
     * @return void
     */
    private function key(Connection $connection, KeyUse $use, KeyState $state, string $certificate, bool $withCertificate = true): void
    {
        $public = openssl_pkey_get_public($certificate);

        self::assertNotFalse($public);

        $details = openssl_pkey_get_details($public);

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => $use,
            'state'         => $state,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $withCertificate ? $certificate : null,
            'public_key'    => is_array($details) ? $details['key'] : '',
            'private_key'   => self::CIPHERTEXT,
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();
    }

    /**
     * The whole metadata document expected for the connection, its signing and
     * encryption certificates, and the options given: `signed`, `wanted`,
     * `format` and `methods`, each defaulted as a connection's setting is.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  list<string>  $signing
     * @param  list<string>  $encryption
     * @param  array{signed?: string, wanted?: string, format?: string, methods?: list<string>}  $options
     * @return string
     */
    private static function expected(Connection $connection, array $signing, array $encryption, array $options = []): string
    {
        $options += ['signed' => 'false', 'wanted' => 'true', 'format' => self::PERSISTENT, 'methods' => self::DEFAULT_METHODS];

        $base    = self::BASE_URL . '/auth/sso/connections/' . $connection->id;
        $methods = implode('', array_map(static fn (string $algorithm): string => '<md:EncryptionMethod Algorithm="' . $algorithm . '"/>', $options['methods']));
        $keys    = [
            ...array_map(static fn (string $certificate): string => self::keyDescriptor('signing', $certificate, ''), $signing),
            ...array_map(static fn (string $certificate): string => self::keyDescriptor('encryption', $certificate, $methods), $encryption),
        ];

        return '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="' . $base . '/metadata">'
            . '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' AuthnRequestsSigned="' . $options['signed'] . '" WantAssertionsSigned="' . $options['wanted'] . '">'
            . implode('', $keys)
            . '<md:NameIDFormat>' . $options['format'] . '</md:NameIDFormat>'
            . '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="' . $base . '/assertions"'
            . ' index="0" isDefault="true"/>'
            . '</md:SPSSODescriptor></md:EntityDescriptor>';
    }

    /**
     * One `KeyDescriptor` expected of the use, the certificate and the methods.
     *
     * @param  string  $use
     * @param  string  $certificate
     * @param  string  $methods
     * @return string
     */
    private static function keyDescriptor(string $use, string $certificate, string $methods): string
    {
        return '<md:KeyDescriptor use="' . $use . '"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>'
            . self::body($certificate) . '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' . $methods . '</md:KeyDescriptor>';
    }

    /**
     * The base64 body of a PEM certificate, on one line.
     *
     * @param  string  $certificate
     * @return string
     */
    private static function body(string $certificate): string
    {
        return (string) preg_replace('/-----[^-]+-----|\s+/', '', $certificate);
    }

    /**
     * The certificate of a key the key service generated.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeySummary  $key
     * @return string
     */
    private static function certificateOf(KeySummary $key): string
    {
        self::assertNotNull($key->key->certificate);

        return $key->key->certificate;
    }

    /**
     * The description's body parsed by the package's hardened parser, valid
     * against the SAML 2.0 metadata schema.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription  $description
     * @return \DOMDocument
     */
    private static function parsed(ServiceProviderDescription $description): \DOMDocument
    {
        return (new HardenedParser)->parse((string) $description->body, MessageKind::METADATA, 1048576);
    }

    /**
     * The `use` of each key descriptor, in document order.
     *
     * @param  \DOMDocument  $document
     * @return list<string>
     */
    private static function keyUses(\DOMDocument $document): array
    {
        return self::values(new \DOMXPath($document), '//md:KeyDescriptor/@use');
    }

    /**
     * The text of each node the query selects, in document order, with the
     * metadata namespace bound to `md`.
     *
     * @param  \DOMXPath  $xpath
     * @param  string  $query
     * @return list<string>
     */
    private static function values(\DOMXPath $xpath, string $query): array
    {
        $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');

        $values = [];

        foreach ($xpath->query($query) ?: [] as $node) {
            $values[] = (string) $node->nodeValue;
        }

        return $values;
    }
}
