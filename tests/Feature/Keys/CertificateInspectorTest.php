<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Keys\CertificateInspector;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for reading and judging an identity provider's signing
 * certificate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CertificateInspector::class)]
final class CertificateInspectorTest extends TestCase
{
    /**
     * Rows of `[certificate, code]`: each certificate refused, and why.
     *
     * @return iterable<string, array{0: \Closure(): string, 1: \SineMacula\Laravel\Sso\Connections\Enums\ViolationCode}>
     */
    public static function provideRefusedCertificates(): iterable
    {
        yield from [
            'longer than the cap'         => [static fn (): string => str_repeat('A', 16385), ViolationCode::TOO_LONG],
            'too long and a private key'  => [static fn (): string => Certificates::privateKey() . str_repeat("\n", 16384), ViolationCode::TOO_LONG],
            'a private key'               => [static fn (): string => Certificates::privateKey(), ViolationCode::PRIVATE_KEY_REFUSED],
            'a certificate and its key'   => [static fn (): string => Certificates::ecP256() . Certificates::privateKey(), ViolationCode::PRIVATE_KEY_REFUSED],
            'not a pem'                   => [static fn (): string => 'not a certificate', ViolationCode::INVALID_FORMAT],
            'empty'                       => [static fn (): string => '', ViolationCode::INVALID_FORMAT],
            'a public key'                => [static fn (): string => (string) MaskedKey::fromCertificate(Certificates::ecP256())->publicKey, ViolationCode::INVALID_FORMAT],
            'two certificates'            => [static fn (): string => Certificates::ecP256() . Certificates::ecP384(), ViolationCode::INVALID_FORMAT],
            'a damaged body'              => [static fn (): string => str_replace('MI', 'xx', Certificates::ecP256()), ViolationCode::INVALID_FORMAT],
            'a file path'                 => [static fn (): string => 'file:///etc/passwd', ViolationCode::INVALID_FORMAT],
            'an rsa 1024 key'             => [static fn (): string => Certificates::rsa1024(), ViolationCode::WEAK_KEY],
            'a curve the package refuses' => [static fn (): string => Certificates::unsupportedCurve(), ViolationCode::WEAK_KEY],
            'an ed25519 key'              => [static fn (): string => Certificates::ED25519, ViolationCode::NOT_ALLOWED],
        ];
    }

    /**
     * Each refused certificate gives exactly one violation, at `certificate`,
     * and no facts.
     *
     * @param  \Closure(): string  $certificate
     * @param  \SineMacula\Laravel\Sso\Connections\Enums\ViolationCode  $code
     * @return void
     */
    #[DataProvider('provideRefusedCertificates')]
    public function testRefusesEachCertificateWithItsCode(\Closure $certificate, ViolationCode $code): void
    {
        $pem = $certificate();

        self::clearOpenSslErrors();

        $inspected = (new CertificateInspector)->inspect($pem);

        self::assertNull($inspected['facts']);
        self::assertCount(1, $inspected['violations']);
        self::assertSame('certificate', $inspected['violations'][0]->setting);
        self::assertSame($code, $inspected['violations'][0]->code);
        self::assertFalse(openssl_error_string());
    }

    /**
     * Rows of `[certificate, type, bits]` for each accepted certificate.
     *
     * @return iterable<string, array{0: \Closure(): string, 1: \SineMacula\Laravel\Sso\Keys\Enums\KeyType, 2: int}>
     */
    public static function provideAcceptedCertificates(): iterable
    {
        yield from [
            'rsa 2048' => [static fn (): string => Certificates::rsa2048(), KeyType::RSA, 2048],
            'ec p-256' => [static fn (): string => Certificates::ecP256(), KeyType::EC, 256],
            'ec p-384' => [static fn (): string => Certificates::ecP384(), KeyType::EC, 384],
            'one day'  => [static fn (): string => Certificates::oneDay(), KeyType::EC, 256],
        ];
    }

    /**
     * An accepted certificate gives its canonical PEM, public key, fingerprint,
     * key type and size, and UTC validity.
     *
     * @param  \Closure(): string  $certificate
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  int  $bits
     * @return void
     */
    #[DataProvider('provideAcceptedCertificates')]
    public function testReadsTheFactsOfAnAcceptedCertificate(\Closure $certificate, KeyType $type, int $bits): void
    {
        $pem = $certificate();

        self::clearOpenSslErrors();

        $inspected = (new CertificateInspector)->inspect($pem);
        $facts     = $inspected['facts'];
        $masked    = MaskedKey::fromCertificate($pem);
        $parsed    = openssl_x509_parse($pem);

        self::assertSame([], $inspected['violations']);
        self::assertNotNull($facts);
        self::assertIsArray($parsed);
        self::assertSame($masked->certificate, $facts['certificate']);
        self::assertSame($masked->publicKey, $facts['public_key']);
        self::assertSame(openssl_x509_fingerprint($pem, 'sha256'), $facts['fingerprint']);
        self::assertSame($type, $facts['type']);
        self::assertSame($bits, $facts['bits']);
        self::assertSame($parsed['validFrom_time_t'], $facts['not_before']->getTimestamp());
        self::assertSame($parsed['validTo_time_t'], $facts['not_after']->getTimestamp());
        self::assertSame('UTC', $facts['not_after']->getTimezone()->getName());
        self::assertFalse(openssl_error_string());
    }

    /**
     * A certificate with other line endings and surrounding whitespace reads as
     * the same canonical certificate.
     *
     * @return void
     */
    public function testReadsACertificateWhateverItsLineEndings(): void
    {
        $pem      = Certificates::ecP256();
        $reworked = "\r\n  " . str_replace("\n", "\r\n", $pem) . "\n\n";

        $facts = (new CertificateInspector)->inspect($reworked)['facts'];

        self::assertNotNull($facts);
        self::assertSame(MaskedKey::fromCertificate($pem)->certificate, $facts['certificate']);
        self::assertSame(openssl_x509_fingerprint($pem, 'sha256'), $facts['fingerprint']);
    }

    /**
     * A certificate of exactly the cap is read; one byte more is too long.
     *
     * @return void
     */
    public function testTheCapIsInclusive(): void
    {
        $pem    = Certificates::ecP256();
        $padded = str_pad($pem, 16384, "\n");

        self::assertSame(16384, strlen($padded));
        self::assertNotNull((new CertificateInspector)->inspect($padded)['facts']);
        self::assertSame(ViolationCode::TOO_LONG, (new CertificateInspector)->inspect($padded . "\n")['violations'][0]->code);
    }

    /**
     * Inspection leaves the error handler it found in place.
     *
     * @return void
     */
    public function testLeavesTheErrorHandlerItFound(): void
    {
        $handler = static fn (): bool => false;

        set_error_handler($handler);

        try {
            $facts = (new CertificateInspector)->inspect(Certificates::ecP256())['facts'];
        } finally {
            $found = set_error_handler(null);

            restore_error_handler();
            restore_error_handler();
        }

        self::assertNotNull($facts);
        self::assertSame($handler, $found);
    }

    /**
     * Empty OpenSSL's error queue so a test sees only what the code under test
     * left.
     *
     * @return void
     */
    private static function clearOpenSslErrors(): void
    {
        do {
            $error = openssl_error_string();
        } while ($error !== false);
    }
}
