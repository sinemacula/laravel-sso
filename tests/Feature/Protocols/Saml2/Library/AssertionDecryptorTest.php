<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SimpleSAML\SAML2\XML\saml\EncryptedAssertion;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\AssertionDecryptor;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\AssertionEncryptor;
use Tests\TestCase;

/**
 * Tests of where the assertion decryptor finds an encrypted assertion's session
 * key.
 *
 * The library is named here only to build the encrypted assertion as the
 * adapter does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AssertionDecryptor::class)]
final class AssertionDecryptorTest extends TestCase
{
    /** @var string The plaintext every case encrypts. */
    private const string PLAINTEXT = '<saml:Assertion/>';

    /** @var ?array{0: string, 1: string} The service provider's encryption key and certificate, made once. */
    private static ?array $spKeys = null;

    /**
     * Rows of `[placement, decrypts]`: where the encrypted keys sit, and
     * whether the assertion decrypts.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideKeyPlacements(): iterable
    {
        yield from [
            'one key in the key info'                => ['inline', true],
            'one key beside the encrypted data'      => ['beside', true],
            'one key after a key name'               => ['named', true],
            'no key'                                 => ['none', false],
            'two keys in the key info'               => ['inline-twice', false],
            'one key in the key info and one beside' => ['both', false],
        ];
    }

    /**
     * Every encrypted key counts, in the key info or beside the encrypted data,
     * and only exactly one decrypts.
     *
     * @param  string  $placement
     * @param  bool  $decrypts
     * @return void
     */
    #[DataProvider('provideKeyPlacements')]
    public function testEveryEncryptedKeyCountsWhereverItIsPlaced(string $placement, bool $decrypts): void
    {
        $encrypted = (new AssertionEncryptor)->encrypt(self::PLAINTEXT, self::spKeys()[1]);

        self::assertSame(1, preg_match('#<ds:KeyInfo[^>]*>(<xenc:EncryptedKey>.*</xenc:EncryptedKey>)</ds:KeyInfo>#', $encrypted, $match));

        [$keyInfo, $key] = $match;
        $beside          = str_replace('<xenc:EncryptedKey>', '<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">', $key) . '</saml:EncryptedAssertion>';

        $xml = match ($placement) {
            'beside'       => str_replace([$keyInfo, '</saml:EncryptedAssertion>'], ['', $beside], $encrypted),
            'none'         => str_replace($keyInfo, '', $encrypted),
            'named'        => str_replace('<xenc:EncryptedKey>', '<ds:KeyName>sp.example.test</ds:KeyName><xenc:EncryptedKey>', $encrypted),
            'inline-twice' => str_replace($key, $key . $key, $encrypted),
            'both'         => str_replace('</saml:EncryptedAssertion>', $beside, $encrypted),
            default        => $encrypted,
        };

        $document = new \DOMDocument;
        $keys     = static fn (): array => [new Secret(self::spKeys()[0])];
        $policy   = new ResponsePolicy([], [], Saml2Settings::KEY_TRANSPORT_ALGORITHMS, Saml2Settings::DATA_ENCRYPTION_ALGORITHMS, $keys);

        self::assertTrue($document->loadXML($xml));

        $root = $document->documentElement ?? self::fail('The document has no root.');

        try {
            $plaintext = (new AssertionDecryptor)->decrypt(EncryptedAssertion::fromXML($root), $policy, false, 4096);
        } catch (ReadFailure $failure) {
            $plaintext = [$failure->reason, $failure->detail];
        }

        self::assertSame($decrypts ? self::PLAINTEXT : [FailureReason::DECRYPTION_FAILED, 'decryption'], $plaintext);
    }

    /**
     * The service provider's encryption key and certificate.
     *
     * @return array{0: string, 1: string}
     */
    private static function spKeys(): array
    {
        return self::$spKeys ??= FakeSamlIdentityProvider::keyPair('sp.example.test');
    }
}
