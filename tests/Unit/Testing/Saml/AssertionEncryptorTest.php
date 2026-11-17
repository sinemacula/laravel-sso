<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Saml;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\AssertionEncryptor;

/**
 * Unit tests for the fake identity provider's assertion encryption.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AssertionEncryptor::class)]
final class AssertionEncryptorTest extends TestCase
{
    /** @var string The assertion encrypted. */
    private const string ASSERTION = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion"/>';

    /** @var string The XML encryption namespace. */
    private const string NS_XENC = 'http://www.w3.org/2001/04/xmlenc#';

    /** @var ?array{0: string, 1: string} The service provider's private key and certificate, made once. */
    private static ?array $keyPair = null;

    /**
     * Rows of `[key transport, data algorithm]`: every pairing.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideAlgorithms(): iterable
    {
        foreach (array_keys(AssertionEncryptor::KEY_TRANSPORTS) as $transport) {
            foreach (array_keys(AssertionEncryptor::DATA_ALGORITHMS) as $data) {
                yield $transport . ' with ' . $data => [$transport, $data];
            }
        }
    }

    /**
     * The private key decrypts the session key, and the session key the
     * assertion, under the algorithms the encrypted assertion names.
     *
     * @param  string  $transport
     * @param  string  $data
     * @return void
     */
    #[DataProvider('provideAlgorithms')]
    public function testEncryptsForTheCertificate(string $transport, string $data): void
    {
        [$privateKey, $certificate] = self::keyPair();

        $xpath = self::xpath((new AssertionEncryptor)->encrypt(self::ASSERTION, $certificate, $transport, $data));

        [$dataUri, $cipher]       = AssertionEncryptor::DATA_ALGORITHMS[$data];
        [$transportUri, $padding] = AssertionEncryptor::KEY_TRANSPORTS[$transport];

        self::assertSame($dataUri, $xpath->evaluate('string(/saml:EncryptedAssertion/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm)'));
        self::assertSame($transportUri, $xpath->evaluate('string(//xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm)'));
        self::assertTrue(openssl_private_decrypt(self::cipherValue($xpath, '//xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue'), $key, $privateKey, $padding));
        self::assertSame(self::ASSERTION, self::decrypt(self::cipherValue($xpath, '/saml:EncryptedAssertion/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue'), $cipher, $key));
    }

    /**
     * A certificate whose key cannot carry an RSA key transport is refused.
     *
     * @return void
     */
    public function testRefusesACertificateWithoutAnRsaKey(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        self::assertNotFalse($key);

        $csr = openssl_csr_new(['commonName' => 'sp.example.test'], $key);

        self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);

        $cert = openssl_csr_sign($csr, null, $key, 1);

        self::assertNotFalse($cert);
        self::assertTrue(openssl_x509_export($cert, $certificate));

        $this->expectExceptionObject(new \LogicException('The fake identity provider could not encrypt the session key.'));

        (new AssertionEncryptor)->encrypt(self::ASSERTION, $certificate);
    }

    /**
     * The plaintext of the IV, ciphertext and, for GCM, tag.
     *
     * @param  string  $value
     * @param  string  $cipher
     * @param  string  $key
     * @return false|string
     */
    private static function decrypt(string $value, string $cipher, string $key): false|string
    {
        if (str_ends_with($cipher, '-gcm')) {
            return openssl_decrypt(substr($value, 12, -16), $cipher, $key, OPENSSL_RAW_DATA, substr($value, 0, 12), substr($value, -16));
        }

        return openssl_decrypt(substr($value, 16), $cipher, $key, OPENSSL_RAW_DATA, substr($value, 0, 16));
    }

    /**
     * The decoded `CipherValue` at the path.
     *
     * @param  \DOMXPath  $xpath
     * @param  string  $path
     * @return string
     */
    private static function cipherValue(\DOMXPath $xpath, string $path): string
    {
        $nodes = $xpath->query($path);
        $value = $nodes === false ? false : base64_decode((string) $nodes->item(0)?->nodeValue, true);

        return $value === false ? self::fail('The cipher value is not base64.') : $value;
    }

    /**
     * An XPath over the XML, with the SAML and XML encryption prefixes.
     *
     * @param  string  $xml
     * @return \DOMXPath
     */
    private static function xpath(string $xml): \DOMXPath
    {
        $document = new \DOMDocument;

        self::assertTrue($document->loadXML($xml));

        $xpath = new \DOMXPath($document);

        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('xenc', self::NS_XENC);

        return $xpath;
    }

    /**
     * The service provider's private key and certificate.
     *
     * @return array{0: string, 1: string}
     */
    private static function keyPair(): array
    {
        return self::$keyPair ??= FakeSamlIdentityProvider::keyPair('sp.example.test');
    }
}
