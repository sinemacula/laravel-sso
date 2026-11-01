<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\GeneratedKey;
use SineMacula\Laravel\Sso\Keys\KeyGenerator;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;
use Tests\TestCase;

/**
 * Feature tests for the generation of the service provider's own key pairs
 * (SSO-2.7): RSA 3072 by default and 4096 when configured, EC on P-256; a
 * self-signed certificate that verifies with its own key, names the common name
 * alone, is signed with SHA-256, carries a positive serial and is valid for the
 * configured days; and a private key held only in a secret, which no dump or
 * serialisation shows (SSO-2.5).
 *
 * RSA generation is slow, so the class generates one RSA 3072 key, one RSA 4096
 * key and EC keys otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyGenerator::class)]
#[CoversClass(GeneratedKey::class)]
final class KeyGeneratorTest extends TestCase
{
    /** @var string The common name every key is generated for: a connection's id. */
    private const string COMMON_NAME = '01jbconnection000000000001';

    /** @var ?\SineMacula\Laravel\Sso\Keys\GeneratedKey The RSA key generated with the default modulus, kept for the class. */
    private static ?GeneratedKey $rsa = null;

    /**
     * An RSA key has a modulus of 3072 bits by default, and a certificate that
     * verifies with its own key.
     *
     * @return void
     */
    public function testGeneratesRsa3072ByDefault(): void
    {
        $key = $this->rsa();

        self::assertSame(KeyType::RSA, $key->type);
        self::assertSame(3072, $key->bits);
        self::assertSame(3072, self::details($key->publicKey)['bits']);
        self::assertSame(OPENSSL_KEYTYPE_RSA, self::details($key->publicKey)['type']);
        self::assertSame(1, openssl_x509_verify($key->certificate, $key->publicKey));
        self::assertSame('RSA-SHA256', self::parse($key->certificate)['signatureTypeSN']);
    }

    /**
     * An RSA key has a modulus of 4096 bits when so configured.
     *
     * @return void
     */
    public function testGeneratesRsa4096WhenConfigured(): void
    {
        config()->set('sso.keys.rsa_bits', 4096);

        $key = $this->generator()->generate(KeyType::RSA, self::COMMON_NAME);

        self::assertSame(4096, $key->bits);
        self::assertSame(4096, self::details($key->publicKey)['bits']);
    }

    /**
     * An elliptic curve key is on P-256, whatever the RSA modulus configured,
     * with a certificate that verifies with its own key.
     *
     * @return void
     */
    public function testGeneratesEcOnP256(): void
    {
        config()->set('sso.keys.rsa_bits', 4096);

        $key     = $this->generator()->generate(KeyType::EC, self::COMMON_NAME);
        $details = self::details($key->publicKey);

        self::assertSame(KeyType::EC, $key->type);
        self::assertSame(256, $key->bits);
        self::assertSame(OPENSSL_KEYTYPE_EC, $details['type']);
        self::assertSame('prime256v1', $details['ec']['curve_name'] ?? null);
        self::assertSame(1, openssl_x509_verify($key->certificate, $key->publicKey));
        self::assertSame('ecdsa-with-SHA256', self::parse($key->certificate)['signatureTypeSN']);
    }

    /**
     * The certificate is self-signed for the common name alone, is not a
     * certificate authority's, and carries a positive serial number of its own.
     *
     * @return void
     */
    public function testTheCertificateNamesTheCommonNameAlone(): void
    {
        $one = self::parse($this->generator()->generate(KeyType::EC, self::COMMON_NAME)->certificate);
        $two = self::parse($this->generator()->generate(KeyType::EC, self::COMMON_NAME)->certificate);

        self::assertSame(['CN' => self::COMMON_NAME], $one['subject']);
        self::assertSame(['CN' => self::COMMON_NAME], $one['issuer']);
        self::assertSame(['basicConstraints' => 'CA:FALSE'], $one['extensions'] ?? null);
        self::assertIsString($one['serialNumber']);
        self::assertMatchesRegularExpression('/^[1-9][0-9]*$/', $one['serialNumber']);
        self::assertNotSame($one['serialNumber'], $two['serialNumber']);
    }

    /**
     * The certificate is valid from when it was signed for the configured days,
     * and the key reports the same dates, in UTC.
     *
     * @return void
     */
    public function testTheCertificateIsValidForTheConfiguredDays(): void
    {
        config()->set('sso.keys.certificate_days', 5);

        $before = time();
        $key    = $this->generator()->generate(KeyType::EC, self::COMMON_NAME);
        $parsed = self::parse($key->certificate);

        self::assertIsInt($parsed['validTo_time_t']);
        self::assertIsInt($parsed['validFrom_time_t']);
        self::assertSame(5 * 86400, $parsed['validTo_time_t'] - $parsed['validFrom_time_t']);
        self::assertGreaterThanOrEqual($before, $parsed['validFrom_time_t']);
        self::assertLessThanOrEqual(time(), $parsed['validFrom_time_t']);
        self::assertSame($parsed['validFrom_time_t'], $key->notBefore->getTimestamp());
        self::assertSame($parsed['validTo_time_t'], $key->notAfter->getTimestamp());
        self::assertSame('UTC', $key->notAfter->getTimezone()->getName());
    }

    /**
     * The certificate and public key are canonical PEM, and the fingerprint is
     * the SHA-256 of the certificate's DER, as a masked key reads it.
     *
     * @return void
     */
    public function testTheFingerprintIsTheCertificates(): void
    {
        $key    = $this->generator()->generate(KeyType::EC, self::COMMON_NAME);
        $masked = MaskedKey::fromCertificate($key->certificate);

        self::assertSame($masked->certificate, $key->certificate);
        self::assertSame($masked->publicKey, $key->publicKey);
        self::assertSame($masked->fingerprint, $key->fingerprint);
        self::assertSame(openssl_x509_fingerprint($key->certificate, 'sha256'), $key->fingerprint);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $key->fingerprint);
    }

    /**
     * The private key is held only in the secret: it is the public key's
     * private half, unencrypted PKCS #8, and leaves the object through
     * `reveal()` alone.
     *
     * @return void
     */
    public function testThePrivateKeyIsHeldOnlyInTheSecret(): void
    {
        $key     = $this->generator()->generate(KeyType::EC, self::COMMON_NAME);
        $pem     = $key->privateKey->reveal();
        $private = openssl_pkey_get_private($pem);

        self::assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $pem);
        self::assertNotFalse($private);
        self::assertSame($key->publicKey, openssl_pkey_get_details($private)['key'] ?? null);

        foreach (self::views($key) as $view) {
            self::assertStringNotContainsString('PRIVATE KEY', $view);
            self::assertStringNotContainsString(substr($pem, 28, 40), $view);
        }

        self::assertSame('[redacted]', $key->__debugInfo()['privateKey']);
        self::assertSame(self::COMMON_NAME, self::parse($key->__debugInfo()['certificate'])['subject']['CN']);
    }

    /**
     * A generated key refuses to be serialised.
     *
     * @return void
     */
    public function testRefusesToBeSerialized(): void
    {
        $key = $this->generator()->generate(KeyType::EC, self::COMMON_NAME);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A generated key cannot be serialised.');

        serialize($key);
    }

    /**
     * A generated key refuses to be unserialised.
     *
     * @return void
     */
    public function testRefusesToBeUnserialized(): void
    {
        $key = $this->generator()->generate(KeyType::EC, self::COMMON_NAME);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A generated key cannot be unserialised.');

        $key->__unserialize([]);
    }

    /**
     * Generation leaves nothing in OpenSSL's error queue for a later call.
     *
     * @return void
     */
    public function testLeavesOpensslsErrorQueueEmpty(): void
    {
        self::clearOpenSslErrors();

        $this->generator()->generate(KeyType::EC, self::COMMON_NAME);

        self::assertFalse(openssl_error_string());
    }

    /**
     * Generation leaves the error handler it found in place.
     *
     * @return void
     */
    public function testLeavesTheErrorHandlerItFound(): void
    {
        $handler = static fn (): bool => false;

        set_error_handler($handler);

        try {
            $this->generator()->generate(KeyType::EC, self::COMMON_NAME);
        } finally {
            $found = set_error_handler(null);

            restore_error_handler();
            restore_error_handler();
        }

        self::assertSame($handler, $found);
    }

    /**
     * The OpenSSL configuration written for a generation is removed after it.
     * Another process may be generating at the same time, so each configuration
     * present just after is waited on for a moment: another process's goes, and
     * only one that stays is counted as left.
     *
     * @return void
     */
    public function testRemovesItsOpensslConfiguration(): void
    {
        $pattern = rtrim(sys_get_temp_dir(), '/') . '/sso-openssl-*';
        $before  = glob($pattern) ?: [];

        $this->generator()->generate(KeyType::EC, self::COMMON_NAME);

        $deadline = microtime(true) + 5;
        $left     = array_values(array_diff(glob($pattern) ?: [], $before));

        while ($left !== [] && microtime(true) < $deadline) {
            usleep(10000);

            $left = array_values(array_intersect($left, glob($pattern) ?: []));
        }

        self::assertSame([], $left);
    }

    /**
     * A dump shows every field but the private key, each as it is held.
     *
     * @return void
     */
    public function testADumpShowsEveryFieldButThePrivateKey(): void
    {
        $key = $this->generator()->generate(KeyType::EC, self::COMMON_NAME);

        self::assertSame([
            'privateKey'  => '[redacted]',
            'publicKey'   => $key->publicKey,
            'certificate' => $key->certificate,
            'type'        => 'ec',
            'bits'        => 256,
            'notBefore'   => $key->notBefore->format('Y-m-d\TH:i:s\Z'),
            'notAfter'    => $key->notAfter->format('Y-m-d\TH:i:s\Z'),
            'fingerprint' => $key->fingerprint,
        ], $key->__debugInfo());
    }

    /**
     * Rows of `[common name]`: names a certificate cannot hold.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedCommonNames(): iterable
    {
        yield from [
            'empty'    => [''],
            'too long' => [str_repeat('a', 65)],
        ];
    }

    /**
     * A common name a certificate cannot hold is the caller's mistake, refused
     * before any key is generated.
     *
     * @param  string  $commonName
     * @return void
     */
    #[DataProvider('provideRefusedCommonNames')]
    public function testRefusesACommonNameACertificateCannotHold(string $commonName): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A certificate\'s common name is 1 to 64 bytes.');

        $this->generator()->generate(KeyType::EC, $commonName);
    }

    /**
     * The longest common name a certificate holds is accepted.
     *
     * @return void
     */
    public function testAcceptsTheLongestCommonName(): void
    {
        $name = str_repeat('a', 64);

        self::assertSame($name, self::parse($this->generator()->generate(KeyType::EC, $name)->certificate)['subject']['CN']);
    }

    /**
     * A malformed setting fails closed, naming its key, before any key is
     * generated.
     *
     * @return void
     */
    public function testAMalformedSettingFailsClosed(): void
    {
        config()->set('sso.keys.rsa_bits', 2048);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('sso.keys.rsa_bits must be one of 3072, 4096.');

        $this->generator()->generate(KeyType::RSA, self::COMMON_NAME);
    }

    /**
     * The RSA key generated with the default modulus, once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Keys\GeneratedKey
     */
    private function rsa(): GeneratedKey
    {
        return self::$rsa ??= $this->generator()->generate(KeyType::RSA, self::COMMON_NAME);
    }

    /**
     * The generator, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyGenerator
     */
    private function generator(): KeyGenerator
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(KeyGenerator::class);
    }

    /**
     * The public key's details, as OpenSSL reads them.
     *
     * @param  string  $publicKey
     * @return array<string, mixed>
     */
    private static function details(string $publicKey): array
    {
        $key     = openssl_pkey_get_public($publicKey);
        $details = $key === false ? false : openssl_pkey_get_details($key);

        self::assertIsArray($details);

        return $details;
    }

    /**
     * The certificate, as OpenSSL parses it.
     *
     * @param  string  $certificate
     * @return array<string, mixed>
     */
    private static function parse(string $certificate): array
    {
        $parsed = openssl_x509_parse($certificate);

        self::assertIsArray($parsed);

        return $parsed;
    }

    /**
     * What the key looks like through each way PHP and Laravel's tooling show
     * an object: Symfony's VarDumper (behind `dump()` and `dd()`), `print_r()`,
     * `var_export()`, an array cast and JSON.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\GeneratedKey  $key
     * @return list<string>
     */
    private static function views(GeneratedKey $key): array
    {
        return [
            (string) (new CliDumper)->dump((new VarCloner)->cloneVar($key), true),
            print_r($key, true),
            var_export($key, true),
            print_r((array) $key, true),
            (string) json_encode((array) $key),
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
}
