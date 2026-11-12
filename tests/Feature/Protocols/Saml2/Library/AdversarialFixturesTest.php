<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\AssertionDecryptor;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\AssertionMapper;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\PinnedVerifier;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\ResponseReader;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\SamlAdapter;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ReadResult;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\TestCase;

/**
 * Feature tests for the adversarial SAML fixtures, read through the adapter.
 *
 * The AES-256-GCM fixture stays refused until saml2 v7.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SamlAdapter::class)]
#[CoversClass(HardenedParser::class)]
#[CoversClass(ResponseReader::class)]
#[CoversClass(PinnedVerifier::class)]
#[CoversClass(AssertionDecryptor::class)]
#[CoversClass(AssertionMapper::class)]
#[CoversClass(ReadResult::class)]
final class AdversarialFixturesTest extends TestCase
{
    /** @var string The fixtures' directory. */
    private const string FIXTURES = __DIR__ . '/../../../../Fixtures/Saml';

    /** @var string What the external entity fixtures would read. */
    private const string SECRET = 'XXE-SECRET';

    /** @var string AES-128-CBC. */
    private const string AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';

    /**
     * Rows of `[name, expect, package]`: each fixture, the outcome required,
     * and the outcome the package gives.
     *
     * @return iterable<string, array{0: string, 1: string, 2: array<string, mixed>}>
     */
    public static function provideFixtures(): iterable
    {
        foreach (self::manifest()['fixtures'] as $fixture) {
            yield $fixture['name'] => [$fixture['name'], $fixture['expect'], $fixture['package']];
        }
    }

    /**
     * The fixture is read, or refused for the reason and rule, as the manifest
     * records.
     *
     * @param  string  $name
     * @param  string  $expect
     * @param  array<string, mixed>  $package
     * @return void
     */
    #[DataProvider('provideFixtures')]
    public function testEachFixtureHasTheOutcomeTheManifestRecords(string $name, string $expect, array $package): void
    {
        $result = $this->read($name);

        if ($package['outcome'] === 'read') {
            self::assertTrue($result->isRead(), (string) $result->detail);
            self::assertSame($package['subject'], $result->response?->assertion()?->subject()?->nameId()?->value());
            self::assertNull($result->reason);
            self::assertNull($result->detail);

            return;
        }

        self::assertFalse($result->isRead());
        self::assertNull($result->response);
        self::assertSame([$package['reason'], $package['detail']], [$result->reason?->value, $result->detail]);
        self::assertTrue($expect !== 'accept' || $name === '04-valid-encrypted-oaep-gcm', "{$name} must be accepted.");
    }

    /**
     * The package is never laxer than required, and every fixture read yields
     * the legitimate subject or the whole signed `NameID`.
     *
     * @param  string  $name
     * @param  string  $expect
     * @param  array<string, mixed>  $package
     * @return void
     */
    #[DataProvider('provideFixtures')]
    public function testThePackageIsNeverLaxerThanTheRequirement(string $name, string $expect, array $package): void
    {
        $result  = $this->read($name);
        $subject = $result->response?->assertion()?->subject()?->nameId()?->value();
        $legit   = self::manifest()['subject'];

        match ($expect) {
            'refuse'      => self::assertFalse($result->isRead(), $name),
            'accept-full' => self::assertContains($subject, [null, $legit . '.mallory'], $name),
            default       => self::assertContains($subject, [null, $legit], $name),
        };

        self::assertStringNotContainsString(self::SECRET, (string) $subject . $result->detail);
        self::assertSame($package['outcome'] === 'read', $result->isRead());
    }

    /**
     * With AES-CBC listed, a signed response's AES-128-CBC assertion is read,
     * the response signature verified before decryption.
     *
     * @return void
     */
    public function testAesCbcDecryptsWhenListedAfterAVerifiedResponseSignature(): void
    {
        $result = $this->read('64-encrypted-oaep-cbc', [...Saml2Settings::DATA_ENCRYPTION_ALGORITHMS, self::AES128_CBC]);

        $response  = $result->response;
        $assertion = $response?->assertion();

        self::assertNotNull($response);
        self::assertNotNull($assertion);
        self::assertTrue($response->isSigned());
        self::assertTrue($assertion->isEncrypted());
        self::assertSame('alice-persistent-id', $assertion->subject()?->nameId()?->value());
    }

    /**
     * RSA 1.5 key transport is refused even with AES-CBC listed, with the one
     * decryption failure.
     *
     * @return void
     */
    public function testRsaOnePointFiveIsRefusedWhateverDataAlgorithmIsListed(): void
    {
        $result = $this->read('62-encrypted-rsa15-cbc', [...Saml2Settings::DATA_ENCRYPTION_ALGORITHMS, self::AES128_CBC]);

        self::assertSame(['decryption_failed', 'decryption'], [$result->reason?->value, $result->detail]);
    }

    /**
     * The manifest names every fixture in the directory once, and only those.
     *
     * @return void
     */
    public function testTheManifestNamesEveryFixtureOnce(): void
    {
        $files = array_map(static fn (string $path): string => basename($path, '.xml'), glob(self::FIXTURES . '/responses/*.xml') ?: []);
        $names = array_column(self::manifest()['fixtures'], 'name');

        sort($files);

        self::assertCount(40, $names);
        self::assertSame($files, $names);
    }

    /**
     * Read the fixture through the adapter, its placeholders filled in, under
     * the default policy or the data encryption algorithms given.
     *
     * @param  string  $name
     * @param  list<string>  $data
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ReadResult
     */
    private function read(string $name, array $data = Saml2Settings::DATA_ENCRYPTION_ALGORITHMS): ReadResult
    {
        $policy = new ResponsePolicy(
            [(string) file_get_contents(self::FIXTURES . '/keys/idp.crt')],
            Saml2Settings::SIGNATURE_ALGORITHMS,
            Saml2Settings::KEY_TRANSPORT_ALGORITHMS,
            $data,
            static fn (): array => [new Secret((string) file_get_contents(self::FIXTURES . '/keys/sp.key'))],
        );

        return app(SamlAdapter::class)->readResponse(base64_encode(self::fixture($name)), $policy);
    }

    /**
     * The fixture's bytes, with the fixtures' directory in place of its
     * placeholder, in the fixture's own encoding.
     *
     * @param  string  $name
     * @return string
     */
    private static function fixture(string $name): string
    {
        $xml       = (string) file_get_contents(self::FIXTURES . '/responses/' . $name . '.xml');
        $directory = (string) realpath(self::FIXTURES);

        if (!str_starts_with($xml, "\xFF\xFE")) {
            return str_replace('{{FIXTURES}}', $directory, $xml);
        }

        $utf8 = str_replace('{{FIXTURES}}', $directory, mb_convert_encoding(substr($xml, 2), 'UTF-8', 'UTF-16LE'));

        return "\xFF\xFE" . mb_convert_encoding($utf8, 'UTF-16LE', 'UTF-8');
    }

    /**
     * The fixtures' manifest.
     *
     * @return array{subject: string, fixtures: list<array{name: string, expect: string, package: array<string, mixed>}>}
     */
    private static function manifest(): array
    {
        /** @var array{subject: string, fixtures: list<array{name: string, expect: string, package: array<string, mixed>}>} */
        return json_decode((string) file_get_contents(self::FIXTURES . '/manifest.json'), true, flags: JSON_THROW_ON_ERROR);
    }
}
