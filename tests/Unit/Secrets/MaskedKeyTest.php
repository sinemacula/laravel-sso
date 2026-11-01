<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;

/**
 * Unit tests for a masked key or certificate: the certificate, the public key
 * and the SHA-256 fingerprint of the DER, read from a self-signed certificate
 * and an RSA key made for the test; a private key refused; a malformed PEM
 * refused without being echoed; and an unset key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MaskedKey::class)]
final class MaskedKeyTest extends TestCase
{
    /** @var ?array<string, string> The test's certificate and keys, made once. */
    private static ?array $pair = null;

    /**
     * A certificate gives itself, its public key and the fingerprint OpenSSL
     * computes of it.
     *
     * @return void
     */
    public function testReadsACertificate(): void
    {
        $pair   = self::pair();
        $masked = MaskedKey::fromCertificate($pair['certificate']);

        self::assertTrue($masked->isSet);
        self::assertSame($pair['certificate'], $masked->certificate);
        self::assertSame($pair['public_key'], $masked->publicKey);
        self::assertSame(openssl_x509_fingerprint($pair['certificate'], 'sha256'), $masked->fingerprint);
        self::assertSame(hash('sha256', self::der($pair['certificate'])), $masked->fingerprint);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $masked->fingerprint);
    }

    /**
     * Surrounding whitespace and other line breaks read as the same
     * certificate, given back in OpenSSL's canonical form.
     *
     * @return void
     */
    public function testReadsACertificateInAnotherLayout(): void
    {
        $pair   = self::pair();
        $masked = MaskedKey::fromCertificate("\n  " . str_replace("\n", "\r\n", $pair['certificate']) . "\n\n");

        self::assertSame($pair['certificate'], $masked->certificate);
        self::assertSame(openssl_x509_fingerprint($pair['certificate'], 'sha256'), $masked->fingerprint);
    }

    /**
     * A public key gives itself and the SHA-256 of its DER, the same key a
     * certificate for it gives, and no certificate.
     *
     * @return void
     */
    public function testReadsAPublicKey(): void
    {
        $pair   = self::pair();
        $masked = MaskedKey::fromPublicKey($pair['public_key']);

        self::assertTrue($masked->isSet);
        self::assertNull($masked->certificate);
        self::assertSame($pair['public_key'], $masked->publicKey);
        self::assertSame(MaskedKey::fromCertificate($pair['certificate'])->publicKey, $masked->publicKey);
        self::assertSame(hash('sha256', self::der($pair['public_key'])), $masked->fingerprint);
        self::assertNotSame(MaskedKey::fromCertificate($pair['certificate'])->fingerprint, $masked->fingerprint);
    }

    /**
     * Rows of `[pem]`: PEMs that hold a private key.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function providePrivateKeys(): iterable
    {
        $pair = self::pair();

        yield 'a private key' => [$pair['private_key']];
        yield 'a certificate with its private key' => [$pair['certificate'] . $pair['private_key']];
        yield 'a public key with its private key' => [$pair['public_key'] . $pair['private_key']];
        yield 'an RSA private key block' => [sprintf("-----BEGIN %1\$s-----\nAAAA\n-----END %1\$s-----\n", 'RSA PRIVATE KEY')];
    }

    /**
     * A private key is never masked, from either kind of PEM, and the refusal
     * does not echo it.
     *
     * @param  string  $pem
     * @return void
     */
    #[DataProvider('providePrivateKeys')]
    public function testRefusesAPrivateKey(string $pem): void
    {
        foreach ([MaskedKey::fromCertificate(...), MaskedKey::fromPublicKey(...)] as $read) {
            try {
                $read($pem);

                self::fail('Expected the private key to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A masked key never holds a private key; give the certificate or the public key.', $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[pem]`: what is not one PEM-encoded certificate.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedCertificates(): iterable
    {
        $pair = self::pair();

        yield 'empty' => [''];
        yield 'not a PEM' => ['not a certificate at all'];
        yield 'a file path' => ['file:///etc/ssl/cert.pem'];
        yield 'a garbled body' => ["-----BEGIN CERTIFICATE-----\nAAAAnotacertificateAAAA\n-----END CERTIFICATE-----\n"];
        yield 'a public key' => [$pair['public_key']];
        yield 'two certificates' => [$pair['certificate'] . $pair['certificate']];
        yield 'text before the block' => ["subject=sso.example.com\n" . $pair['certificate']];
    }

    /**
     * A malformed certificate is refused, the refusal never echoes it, and
     * nothing is left in OpenSSL's error queue.
     *
     * @param  string  $pem
     * @return void
     */
    #[DataProvider('provideMalformedCertificates')]
    public function testRefusesAMalformedCertificate(string $pem): void
    {
        self::clearOpenSslErrors();

        try {
            MaskedKey::fromCertificate($pem);

            self::fail('Expected the certificate to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('The certificate is not one PEM-encoded X.509 certificate.', $exception->getMessage());
            self::assertFalse(openssl_error_string());
        }
    }

    /**
     * Rows of `[pem]`: what is not one PEM-encoded public key.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedPublicKeys(): iterable
    {
        $pair = self::pair();

        yield 'empty' => [''];
        yield 'not a PEM' => ['not a key at all'];
        yield 'a file path' => ['file:///etc/ssl/key.pem'];
        yield 'a garbled body' => ["-----BEGIN PUBLIC KEY-----\nAAAAnotakeyAAAA\n-----END PUBLIC KEY-----\n"];
        yield 'a certificate' => [$pair['certificate']];
        yield 'two public keys' => [$pair['public_key'] . $pair['public_key']];
    }

    /**
     * A malformed public key is refused, the refusal never echoes it, and
     * nothing is left in OpenSSL's error queue.
     *
     * @param  string  $pem
     * @return void
     */
    #[DataProvider('provideMalformedPublicKeys')]
    public function testRefusesAMalformedPublicKey(string $pem): void
    {
        self::clearOpenSslErrors();

        try {
            MaskedKey::fromPublicKey($pem);

            self::fail('Expected the public key to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('The public key is not one PEM-encoded public key.', $exception->getMessage());
            self::assertFalse(openssl_error_string());
        }
    }

    /**
     * An unset key reads as unset, with nothing else.
     *
     * @return void
     */
    public function testUnset(): void
    {
        $masked = MaskedKey::unset();

        self::assertFalse($masked->isSet);
        self::assertNull($masked->certificate);
        self::assertNull($masked->publicKey);
        self::assertNull($masked->fingerprint);
    }

    /**
     * Its JSON is the four fields, and never a private key.
     *
     * @return void
     */
    public function testJson(): void
    {
        $pair   = self::pair();
        $masked = MaskedKey::fromCertificate($pair['certificate']);

        self::assertSame([
            'set'         => true,
            'certificate' => $pair['certificate'],
            'public_key'  => $pair['public_key'],
            'fingerprint' => $masked->fingerprint,
        ], $masked->jsonSerialize());

        self::assertSame(
            ['set' => false, 'certificate' => null, 'public_key' => null, 'fingerprint' => null],
            MaskedKey::unset()->jsonSerialize(),
        );

        self::assertStringNotContainsString('PRIVATE', (string) json_encode($masked));
    }

    /**
     * A self-signed certificate, its public key and its private key, made once
     * for the class.
     *
     * @return array<string, string>
     */
    private static function pair(): array
    {
        if (self::$pair !== null) {
            return self::$pair;
        }

        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $key);

        $request = openssl_csr_new(['commonName' => 'sso.example.com'], $key, ['digest_alg' => 'sha256']);

        self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $request);

        $certificate = openssl_csr_sign($request, null, $key, 1, ['digest_alg' => 'sha256']);

        self::assertInstanceOf(\OpenSSLCertificate::class, $certificate);

        $details = openssl_pkey_get_details($key);

        self::assertIsArray($details);
        self::assertIsString($details['key']);
        self::assertTrue(openssl_x509_export($certificate, $certificatePem));
        self::assertTrue(openssl_pkey_export($key, $privatePem));
        self::assertIsString($certificatePem);
        self::assertIsString($privatePem);

        self::clearOpenSslErrors();

        return self::$pair = [
            'certificate' => $certificatePem,
            'public_key'  => $details['key'],
            'private_key' => $privatePem,
        ];
    }

    /**
     * Empty OpenSSL's error queue, so what a test finds there afterwards is
     * what the code under test left.
     *
     * @return void
     */
    private static function clearOpenSslErrors(): void
    {
        do {
            $error = openssl_error_string();
        } while ($error !== false);
    }

    /**
     * The DER a single-block PEM encodes.
     *
     * @param  string  $pem
     * @return string
     */
    private static function der(string $pem): string
    {
        $lines = array_filter(
            explode("\n", trim($pem)),
            static fn (string $line): bool => !str_starts_with($line, '-----'),
        );

        return (string) base64_decode(implode('', $lines), true);
    }
}
