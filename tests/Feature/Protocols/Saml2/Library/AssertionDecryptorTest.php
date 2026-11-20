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

    /** @var array{0: \SineMacula\Laravel\Sso\Events\Enums\FailureReason, 1: string} The one decryption failure. */
    private const array FAILED = [FailureReason::DECRYPTION_FAILED, 'decryption'];

    /** @var ?array{0: string, 1: string} The service provider's encryption key and certificate, made once. */
    private static ?array $spKeys = null;

    /** @var ?array{0: string, 1: string} Another recipient's key and certificate, made once. */
    private static ?array $otherKeys = null;

    /** @var ?string A decryption key of ours that no case encrypts to, made once. */
    private static ?string $spareKey = null;

    /** @var int How many times the policy was asked for its decryption keys. */
    private int $keysAsked = 0;

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
            'two keys in the key info'               => ['inline-twice', true],
            'one key in the key info and one beside' => ['both', true],
        ];
    }

    /**
     * An encrypted key is found in the key info or beside the encrypted data,
     * and an assertion needs at least one.
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

        self::assertSame($decrypts ? self::PLAINTEXT : self::FAILED, $this->decrypt($xml, Saml2Settings::KEY_TRANSPORT_ALGORITHMS));
    }

    /**
     * Rows of `[recipients, decrypts, asked]`: what each encrypted key wraps
     * the session key for, in order, whether the assertion decrypts, and how
     * often our keys were read.
     *
     * @return iterable<string, array{0: list<string>, 1: bool, 2: int}>
     */
    public static function provideEncryptedKeys(): iterable
    {
        yield from [
            'ours alone'                           => [['ours'], true, 1],
            'another recipient, then ours'         => [['other', 'ours'], true, 1],
            'ours, then another recipient'         => [['ours', 'other'], true, 1],
            'several, none ours'                   => [['other', 'other', 'other'], false, 1],
            'at the cap, ours last'                => [['other', 'other', 'other', 'ours'], true, 1],
            'over the cap, ours first'             => [['ours', 'other', 'other', 'other', 'other'], false, 0],
            'ours under a transport not allowed'   => [['unlisted'], false, 0],
            'a transport not allowed, then ours'   => [['unlisted', 'ours'], true, 1],
            'a session key of the wrong length'    => [['short'], false, 1],
            'the wrong length, then the right one' => [['short', 'ours'], true, 1],
            'a session key with bytes to spare'    => [['long'], false, 1],
            'only a wrong session key'             => [['wrong'], false, 1],
            'a wrong session key, then the right'  => [['wrong', 'ours'], true, 1],
            'the right session key, then a wrong'  => [['ours', 'wrong'], true, 1],
            'ours under rsa 1.5, though listed'    => [['rsa15'], false, 0],
        ];
    }

    /**
     * Each encrypted key is tried in turn against each of our keys, up to the
     * cap, until a session key it unwraps decrypts the assertion.
     *
     * @param  list<string>  $recipients
     * @param  bool  $decrypts
     * @param  int  $asked
     * @return void
     */
    #[DataProvider('provideEncryptedKeys')]
    public function testTriesEachEncryptedKeyUpToTheCap(array $recipients, bool $decrypts, int $asked): void
    {
        $encrypted = (new AssertionEncryptor)->encrypt(self::PLAINTEXT, self::spKeys()[1]);

        self::assertSame(1, preg_match('#<xenc:EncryptedKey>.*?<xenc:CipherValue>([^<]+)</xenc:CipherValue>.*?</xenc:EncryptedKey>#', $encrypted, $match));
        self::assertTrue(openssl_private_decrypt((string) base64_decode($match[1], true), $session, self::spKeys()[0], OPENSSL_PKCS1_OAEP_PADDING));

        $keys = implode('', array_map(static fn (string $recipient): string => self::encryptedKey($recipient, (string) $session), $recipients));
        $xml  = str_replace($match[0], $keys, $encrypted);

        $transports = [AssertionEncryptor::KEY_TRANSPORTS['rsa-oaep-mgf1p'][0], AssertionEncryptor::KEY_TRANSPORTS['rsa-1_5'][0]];

        self::assertSame($decrypts ? self::PLAINTEXT : self::FAILED, $this->decrypt($xml, $transports));
        self::assertSame($asked, $this->keysAsked);
    }

    /**
     * Rows of `[offset, decrypts, asked]`: the cap's distance from the
     * plaintext's length, whether the assertion decrypts, and how often our
     * keys were read. AES-GCM adds 28 bytes, inside the 64 allowed.
     *
     * @return iterable<string, array{0: int, 1: bool, 2: int}>
     */
    public static function provideCaps(): iterable
    {
        yield from [
            'at the cap'                        => [0, true, 1],
            'one over the cap'                  => [-1, false, 1],
            'ciphertext at the allowance'       => [-36, false, 1],
            'ciphertext one over the allowance' => [-37, false, 0],
        ];
    }

    /**
     * Ciphertext too long for the cap is refused before any key is read, and
     * plaintext over it once decrypted.
     *
     * @param  int  $offset
     * @param  bool  $decrypts
     * @param  int  $asked
     * @return void
     */
    #[DataProvider('provideCaps')]
    public function testCapsTheCiphertextAndThePlaintext(int $offset, bool $decrypts, int $asked): void
    {
        $plaintext = '<saml:Assertion>' . str_repeat('x', 100) . '</saml:Assertion>';
        $encrypted = (new AssertionEncryptor)->encrypt($plaintext, self::spKeys()[1]);

        self::assertSame($decrypts ? $plaintext : self::FAILED, $this->decrypt($encrypted, Saml2Settings::KEY_TRANSPORT_ALGORITHMS, strlen($plaintext) + $offset));
        self::assertSame($asked, $this->keysAsked);
    }

    /**
     * Decryption keys that cannot be read fail as any other decryption does.
     *
     * @return void
     */
    public function testUnreadableDecryptionKeysFailTheDecryption(): void
    {
        $document = new \DOMDocument;
        $keys     = static fn (): array => throw new \RuntimeException('The key ring cannot be read.');
        $policy   = new ResponsePolicy([], [], Saml2Settings::KEY_TRANSPORT_ALGORITHMS, Saml2Settings::DATA_ENCRYPTION_ALGORITHMS, $keys);

        self::assertTrue($document->loadXML((new AssertionEncryptor)->encrypt(self::PLAINTEXT, self::spKeys()[1])));

        try {
            (new AssertionDecryptor)->decrypt(EncryptedAssertion::fromXML($document->documentElement ?? self::fail('The document has no root.')), $policy, false, 4096);
            self::fail('Unreadable keys decrypted.');
        } catch (ReadFailure $failure) {
            self::assertSame(self::FAILED, [$failure->reason, $failure->detail]);
        }
    }

    /**
     * The plaintext, or the failure's reason and detail, of the encrypted
     * assertion under a policy allowing the transports, with a spare key of
     * ours tried first.
     *
     * @param  string  $xml
     * @param  list<string>  $transports
     * @param  int  $maxBytes
     * @return array{0: \SineMacula\Laravel\Sso\Events\Enums\FailureReason, 1: string}|string
     */
    private function decrypt(string $xml, array $transports, int $maxBytes = 4096): array|string
    {
        $document = new \DOMDocument;
        $keys     = function (): array {
            $this->keysAsked++;

            return [new Secret(self::spareKey()), new Secret(self::spKeys()[0])];
        };

        $policy = new ResponsePolicy([], [], $transports, Saml2Settings::DATA_ENCRYPTION_ALGORITHMS, $keys);

        self::assertTrue($document->loadXML($xml));

        $root = $document->documentElement ?? self::fail('The document has no root.');

        try {
            return (new AssertionDecryptor)->decrypt(EncryptedAssertion::fromXML($root), $policy, false, $maxBytes);
        } catch (ReadFailure $failure) {
            return [$failure->reason, $failure->detail];
        }
    }

    /**
     * An `EncryptedKey` wrapping the session key for the recipient: ours,
     * another's, ours under a transport the policy does not allow or under RSA
     * 1.5, or ours wrapping a session key cut short, run long or replaced.
     *
     * @param  string  $recipient
     * @param  string  $session
     * @return string
     */
    private static function encryptedKey(string $recipient, #[\SensitiveParameter] string $session): string
    {
        [$certificate, $transport, $value] = match ($recipient) {
            'other'    => [self::otherKeys()[1], 'rsa-oaep-mgf1p', $session],
            'unlisted' => [self::spKeys()[1], 'rsa-oaep', $session],
            'short'    => [self::spKeys()[1], 'rsa-oaep-mgf1p', substr($session, 0, 8)],
            'long'     => [self::spKeys()[1], 'rsa-oaep-mgf1p', $session . $session],
            'wrong'    => [self::spKeys()[1], 'rsa-oaep-mgf1p', strrev($session)],
            'rsa15'    => [self::spKeys()[1], 'rsa-1_5', $session],
            default    => [self::spKeys()[1], 'rsa-oaep-mgf1p', $session],
        };

        [$uri, $padding] = AssertionEncryptor::KEY_TRANSPORTS[$transport];

        self::assertTrue(openssl_public_encrypt($value, $wrapped, $certificate, $padding));

        return '<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="' . $uri . '"/><xenc:CipherData><xenc:CipherValue>'
            . base64_encode((string) $wrapped) . '</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>';
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

    /**
     * Another recipient's key and certificate.
     *
     * @return array{0: string, 1: string}
     */
    private static function otherKeys(): array
    {
        return self::$otherKeys ??= FakeSamlIdentityProvider::keyPair('other.example.test');
    }

    /**
     * A decryption key of ours that no case encrypts to.
     *
     * @return string
     */
    private static function spareKey(): string
    {
        return self::$spareKey ??= FakeSamlIdentityProvider::keyPair('spare.example.test')[0];
    }
}
