<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\MetadataWriter;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use Tests\Fixtures\Keys\Certificates;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Feature tests for the service provider metadata writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataWriter::class)]
final class MetadataWriterTest extends TestCase
{
    /** @var string The service provider's entity id. */
    private const string ENTITY_ID = 'https://sp.example.test/saml/metadata';

    /** @var string The assertion consumer service. */
    private const string ACS = 'https://sp.example.test/saml/assertions';

    /** @var string The refusal of a value that is not one PEM certificate. */
    private const string NOT_A_CERTIFICATE = 'A service provider certificate in the metadata must be exactly one PEM-encoded certificate.';

    /** @var string The refusal of metadata the schema does not allow. */
    private const string UNWRITABLE = 'The service provider metadata cannot be written: its entity id, an endpoint or a certificate is not one SAML 2.0 Metadata allows.';

    /** @var string RSA-OAEP key transport (XML Encryption 1.1). */
    private const string RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';

    /** @var string RSA-OAEP key transport with MGF1 over SHA-1. */
    private const string RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

    /** @var string AES-128-GCM. */
    private const string AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';

    /** @var string AES-192-GCM. */
    private const string AES192_GCM = 'http://www.w3.org/2009/xmlenc11#aes192-gcm';

    /** @var string AES-256-GCM. */
    private const string AES256_GCM = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';

    /** @var string AES-256-CBC. */
    private const string AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';

    /** @var string RSA 1.5 key transport. */
    private const string RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';

    /**
     * Every element and attribute is written, the whole document valid against
     * the SAML 2.0 metadata schema.
     *
     * @return void
     */
    public function testWritesEveryElementAndAttribute(): void
    {
        $options = self::samlOptions([
            'sign_authn_requests'    => true,
            'want_assertions_signed' => false,
            'name_id_format'         => 'email',
            'encryption_algorithms'  => [self::RSA_OAEP_MGF1P, self::AES256_CBC, self::AES128_GCM],
        ]);

        $signing    = [Certificates::distinct(0), Certificates::distinct(1)];
        $encryption = [Certificates::distinct(2), Certificates::distinct(3)];
        $methods    = '<md:EncryptionMethod Algorithm="' . self::AES256_CBC . '"/><md:EncryptionMethod Algorithm="' . self::AES128_GCM . '"/>'
            . '<md:EncryptionMethod Algorithm="' . self::RSA_OAEP_MGF1P . '"/>';

        $xml = (new MetadataWriter)->write(self::endpoints(), $options, $signing, $encryption);

        $expected = '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test/saml/metadata">'
            . '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="false">'
            . self::keyDescriptor('signing', $signing[0], '')
            . self::keyDescriptor('signing', $signing[1], '')
            . self::keyDescriptor('encryption', $encryption[0], $methods)
            . self::keyDescriptor('encryption', $encryption[1], $methods)
            . '<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>'
            . '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/saml/assertions"'
            . ' index="0" isDefault="true"/>'
            . '</md:SPSSODescriptor></md:EntityDescriptor>';

        self::assertSame($expected, $xml);
        self::assertSame('EntityDescriptor', self::parsed($xml)->documentElement?->localName);
    }

    /**
     * With the defaults and no certificate, requests are unsigned, assertions
     * must be signed and NameID is persistent.
     *
     * @return void
     */
    public function testWritesTheDefaultsWithNoCertificate(): void
    {
        $xml = (new MetadataWriter)->write(self::endpoints(), self::samlOptions([]), [], []);

        $expected = '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test/saml/metadata">'
            . '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="true">'
            . '<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>'
            . '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/saml/assertions"'
            . ' index="0" isDefault="true"/>'
            . '</md:SPSSODescriptor></md:EntityDescriptor>';

        self::assertSame($expected, $xml);

        self::parsed($xml);
    }

    /**
     * Rows of `[encryption algorithms, methods]`: data algorithms first, each
     * group in the order stored.
     *
     * @return iterable<string, array{0: ?list<string>, 1: list<string>}>
     */
    public static function provideEncryptionAlgorithms(): iterable
    {
        yield from [
            'the default'    => [null, [self::AES128_GCM, self::AES192_GCM, self::RSA_OAEP, self::RSA_OAEP_MGF1P]],
            'one of each'    => [[self::AES192_GCM, self::RSA_OAEP_MGF1P], [self::AES192_GCM, self::RSA_OAEP_MGF1P]],
            'key transports' => [[self::RSA_OAEP_MGF1P, self::AES128_GCM, self::RSA_OAEP], [self::AES128_GCM, self::RSA_OAEP_MGF1P, self::RSA_OAEP]],
            'AES-CBC listed' => [[self::RSA_OAEP, self::AES256_CBC], [self::AES256_CBC, self::RSA_OAEP]],
            'never written'  => [[self::RSA_1_5, self::AES256_GCM, self::RSA_OAEP, self::AES192_GCM], [self::AES192_GCM, self::RSA_OAEP]],
        ];
    }

    /**
     * Each encryption key descriptor carries the methods the allow-list gives,
     * a signing one none, and AES-256-GCM and RSA 1.5 are never written.
     *
     * @param  ?list<string>  $algorithms
     * @param  list<string>  $methods
     * @return void
     */
    #[DataProvider('provideEncryptionAlgorithms')]
    public function testTheEncryptionMethodsFollowTheAllowList(?array $algorithms, array $methods): void
    {
        $options = self::samlOptions($algorithms === null ? [] : ['encryption_algorithms' => $algorithms]);
        $xml     = (new MetadataWriter)->write(self::endpoints(), $options, [Certificates::distinct(0)], [Certificates::distinct(1)]);
        $xpath   = new \DOMXPath(self::parsed($xml));

        $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');

        self::assertSame($methods, self::values($xpath->query('//md:KeyDescriptor[@use="encryption"]/md:EncryptionMethod/@Algorithm')));
        self::assertSame([], self::values($xpath->query('//md:KeyDescriptor[@use="signing"]/md:EncryptionMethod/@Algorithm')));
        self::assertStringNotContainsString(self::AES256_GCM, $xml);
        self::assertStringNotContainsString(self::RSA_1_5, $xml);
    }

    /**
     * Rows of `[certificate]`: a value that is not exactly one PEM certificate
     * block.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNonCertificates(): iterable
    {
        $certificate = Certificates::distinct(0);
        $body        = (string) preg_replace('/-----[^-]+-----|\s+/', '', $certificate);

        yield from [
            'a private key'             => [Certificates::privateKey()],
            'a public key'              => [self::publicKeyOf($certificate)],
            'two certificates'          => [$certificate . $certificate],
            'a certificate and a key'   => [$certificate . Certificates::privateKey()],
            'a key and a certificate'   => [Certificates::privateKey() . $certificate],
            'a bare body'               => [$body],
            'an empty value'            => [''],
            'text before the block'     => ['subject=sp ' . $certificate],
            'text after the block'      => [trim($certificate) . ' trailing'],
            'a body that is not base64' => ["-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"],
            'an empty block'            => ['-----BEGIN CERTIFICATE----------END CERTIFICATE-----'],
            'a file path'               => ['file:///etc/ssl/private/sp.key'],
        ];
    }

    /**
     * Anything but exactly one PEM certificate block is refused, given as a
     * signing or an encryption certificate, quoting nothing of it.
     *
     * @param  string  $certificate
     * @return void
     */
    #[DataProvider('provideNonCertificates')]
    public function testRefusesAnythingButOneCertificate(string $certificate): void
    {
        foreach ([[[$certificate], []], [[], [$certificate]], [[Certificates::distinct(1)], [Certificates::distinct(2), $certificate]]] as [$signing, $encryption]) {
            try {
                (new MetadataWriter)->write(self::endpoints(), self::samlOptions([]), $signing, $encryption);
                self::fail('A value that is not one certificate was written.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::NOT_A_CERTIFICATE, $exception->getMessage());
                self::assertNull($exception->getPrevious());
            }
        }
    }

    /**
     * A certificate is written as its body on one line, however its block is
     * broken or surrounded by whitespace.
     *
     * @return void
     */
    public function testWritesACertificateBodyOnOneLineHoweverItIsBroken(): void
    {
        $certificate = Certificates::distinct(0);
        $body        = (string) preg_replace('/-----[^-]+-----|\s+/', '', $certificate);
        $crlf        = "\r\n  " . str_replace("\n", "\r\n", $certificate) . "\n\n";
        $wrapped     = "-----BEGIN CERTIFICATE-----\n" . implode("\n", str_split($body, 76)) . "\n-----END CERTIFICATE-----";
        $canonical   = (new MetadataWriter)->write(self::endpoints(), self::samlOptions([]), [$certificate], []);

        self::assertStringContainsString('<ds:X509Certificate>' . $body . '</ds:X509Certificate>', $canonical);
        self::assertSame($canonical, (new MetadataWriter)->write(self::endpoints(), self::samlOptions([]), [$crlf], []));
        self::assertSame($canonical, (new MetadataWriter)->write(self::endpoints(), self::samlOptions([]), [$wrapped], []));
    }

    /**
     * An entity id of 1024 characters is written, one of 1025 is refused, and
     * so is a block whose body the schema does not allow, quoting nothing.
     *
     * @return void
     */
    public function testRefusesWhatTheSchemaDoesNotAllow(): void
    {
        $longest = 'https://sp.example.test/' . str_repeat('a', 1000);
        $xml     = (new MetadataWriter)->write(self::endpoints($longest), self::samlOptions([]), [], []);

        self::assertSame(1024, strlen($longest));
        self::assertStringContainsString('entityID="' . $longest . '"', $xml);

        $refusals = [
            'an entity id one character too long' => [self::endpoints($longest . 'a'), []],
            'a body the schema does not allow'    => [self::endpoints(), ["-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"]],
        ];

        foreach ($refusals as $case => [$endpoints, $signing]) {
            try {
                (new MetadataWriter)->write($endpoints, self::samlOptions([]), $signing, []);
                self::fail("{$case} was written.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::UNWRITABLE, $exception->getMessage(), $case);
                self::assertNull($exception->getPrevious(), $case);
            }
        }
    }

    /**
     * The same input always gives the same bytes, with no private key, no PEM
     * armour and no signature.
     *
     * @return void
     */
    public function testWritesTheSameBytesForTheSameInput(): void
    {
        $options = self::samlOptions(['sign_authn_requests' => true]);
        $first   = (new MetadataWriter)->write(self::endpoints(), $options, [Certificates::distinct(0)], [Certificates::distinct(1)]);
        $second  = (new MetadataWriter)->write(self::endpoints(), self::samlOptions(['sign_authn_requests' => true]), [Certificates::distinct(0)], [Certificates::distinct(1)]);

        self::assertSame($first, $second);
        self::assertStringNotContainsString('PRIVATE', $first);
        self::assertStringNotContainsString('-----', $first);
        self::assertStringNotContainsString('ds:Signature', $first);
        self::assertStringNotContainsString(' ID=', $first);
        self::assertStringNotContainsString('validUntil', $first);
        self::assertStringNotContainsString('cacheDuration', $first);
    }

    /**
     * The options of a SAML connection with the settings given.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options
     */
    private static function samlOptions(array $settings): Saml2Options
    {
        return Saml2Options::of(new ExampleConnection('saml2', $settings));
    }

    /**
     * The service provider's endpoints, with the entity id given.
     *
     * @param  string  $entityId
     * @return \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints
     */
    private static function endpoints(string $entityId = self::ENTITY_ID): ConnectionEndpoints
    {
        return new ConnectionEndpoints(self::ACS, 'https://sp.example.test/oidc/callback', $entityId, self::ENTITY_ID, 'https://sp.example.test/oidc/jwks');
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
        $body = (string) preg_replace('/-----[^-]+-----|\s+/', '', $certificate);

        return '<md:KeyDescriptor use="' . $use . '"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>'
            . $body . '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' . $methods . '</md:KeyDescriptor>';
    }

    /**
     * The public key of a certificate, PEM-encoded.
     *
     * @param  string  $certificate
     * @return string
     */
    private static function publicKeyOf(string $certificate): string
    {
        $key     = openssl_pkey_get_public($certificate);
        $details = $key === false ? false : openssl_pkey_get_details($key);

        return is_array($details) ? (string) $details['key'] : '';
    }

    /**
     * The XML parsed by the package's hardened parser, valid against the SAML
     * 2.0 metadata schema.
     *
     * @param  string  $xml
     * @return \DOMDocument
     */
    private static function parsed(string $xml): \DOMDocument
    {
        return (new HardenedParser)->parse($xml, MessageKind::METADATA, 1048576);
    }

    /**
     * The value of each attribute, in document order.
     *
     * @param  \DOMNodeList<\DOMNameSpaceNode|\DOMNode>|false  $nodes
     * @return list<string>
     */
    private static function values(\DOMNodeList|false $nodes): array
    {
        $values = [];

        foreach ($nodes ?: [] as $node) {

            self::assertInstanceOf(\DOMAttr::class, $node);

            $values[] = $node->value;
        }

        return $values;
    }
}
