<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use Illuminate\Contracts\Encryption\DecryptException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Secrets\MaskedSecret;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Feature tests for a connection's secrets column (SSO-2.5): which secrets are
 * set is read and masked without decrypting one, a secret is revealed only by
 * decrypting it, a change sets, replaces, clears or keeps each secret on its
 * own, and a malformed column or a failed decryption never shows a secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionSecrets::class)]
final class ConnectionSecretsTest extends TestCase
{
    use UsesConnections;

    /** @var string A client secret no output may show. */
    private const string SECRET = 'the-client-secret-value';

    /** @var string Another client secret. */
    private const string OTHER = 'another-client-secret';

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

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
     * Which secrets are set, and each declared secret masked, without one being
     * decrypted.
     *
     * @return void
     */
    public function testNamesAndMasksWithoutDecrypting(): void
    {
        $stored  = $this->secrets()->apply(null, ['client_secret' => new Secret(self::SECRET)]);
        $secrets = new ConnectionSecrets(self::refusingToDecrypt());

        $connection = self::connection($stored);

        self::assertSame(['client_secret'], $secrets->names($connection));

        $masked = $secrets->masked($connection, ['client_secret', 'api_secret']);

        self::assertSame(['client_secret', 'api_secret'], array_keys($masked));
        self::assertEquals(MaskedSecret::set(), $masked['client_secret']);
        self::assertEquals(MaskedSecret::unset(), $masked['api_secret']);
        self::assertSame('{"client_secret":{"set":true},"api_secret":{"set":false}}', json_encode($masked));

        self::assertSame([], $secrets->names(self::connection(null)));
        self::assertEquals(['client_secret' => MaskedSecret::unset()], $secrets->masked(self::connection(null), ['client_secret']));
        self::assertSame([], $secrets->masked($connection, []));
    }

    /**
     * A secret is revealed by decrypting it, and `null` when it is not set.
     *
     * @return void
     */
    public function testRevealsASecretByDecryptingIt(): void
    {
        $secrets    = $this->secrets();
        $connection = self::connection($secrets->apply(null, ['client_secret' => new Secret(self::SECRET)]));

        self::assertTrue($secrets->reveal($connection, 'client_secret')?->equals(self::SECRET));
        self::assertNull($secrets->reveal($connection, 'api_secret'));
        self::assertNull($secrets->reveal(self::connection(null), 'client_secret'));
    }

    /**
     * A ciphertext that cannot be decrypted propagates as a server error,
     * Laravel's own `DecryptException`, naming no secret; a test failure is not
     * mistaken for it.
     *
     * @return void
     */
    public function testAFailedDecryptionPropagates(): void
    {
        $connection = self::connection('{"client_secret":"not-a-ciphertext"}');

        try {
            $this->secrets()->reveal($connection, 'client_secret');
            self::fail('The ciphertext was decrypted.');
        } catch (DecryptException $exception) {
            self::assertStringNotContainsString('not-a-ciphertext', $exception->getMessage());
        }

        $this->expectException(\RuntimeException::class);

        (new ConnectionSecrets(self::refusingToDecrypt()))->reveal($connection, 'client_secret');
    }

    /**
     * A secret that decrypts to nothing is refused rather than revealed.
     *
     * @return void
     */
    public function testRefusesASecretThatDecryptsToNothing(): void
    {
        $connection = self::connection('{"client_secret":"' . $this->app?->make(SecretEncrypter::class)->encrypt('') . '"}');

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A stored secret decrypted to nothing.');

        $this->secrets()->reveal($connection, 'client_secret');
    }

    /**
     * A change sets, replaces and clears each secret on its own; a secret not
     * named is kept exactly as stored; and none left is `null`.
     *
     * @return void
     */
    public function testAppliesEachChangeOnItsOwn(): void
    {
        $secrets = $this->secrets();

        $set = $secrets->apply(null, ['client_secret' => new Secret(self::SECRET), 'api_secret' => new Secret(self::OTHER)]);

        self::assertIsString($set);
        self::assertStringNotContainsString(self::SECRET, $set);
        self::assertStringNotContainsString(self::OTHER, $set);
        self::assertSame(['client_secret', 'api_secret'], array_keys((array) json_decode($set, true)));

        $kept = (array) json_decode($set, true);

        $replaced = $secrets->apply($set, ['client_secret' => new Secret(self::OTHER)]);

        self::assertIsString($replaced);

        $decoded = (array) json_decode($replaced, true);

        self::assertNotSame($kept['client_secret'], $decoded['client_secret']);
        self::assertSame($kept['api_secret'], $decoded['api_secret']);
        self::assertTrue($secrets->reveal(self::connection($replaced), 'client_secret')?->equals(self::OTHER));

        $cleared = $secrets->apply($replaced, ['client_secret' => null]);

        self::assertIsString($cleared);
        self::assertSame(['api_secret' => $kept['api_secret']], json_decode($cleared, true));

        self::assertSame($cleared, $secrets->apply($cleared, []));
        self::assertSame($cleared, $secrets->apply($cleared, ['client_secret' => null]));
        self::assertNull($secrets->apply($cleared, ['api_secret' => null]));
        self::assertNull($secrets->apply(null, []));
        self::assertNull($secrets->apply(null, ['client_secret' => null]));
    }

    /**
     * A change clears and sets secrets in one pass, whichever comes first, and
     * the column keeps each ciphertext's slashes as they are.
     *
     * @return void
     */
    public function testAppliesAClearBeforeASetAndKeepsSlashes(): void
    {
        $secrets = new ConnectionSecrets(new class implements SecretEncrypter {
            /**
             * Answer a ciphertext with a slash in it.
             *
             * @param  string  $secret
             * @return string
             */
            #[\Override]
            public function encrypt(#[\SensitiveParameter] string $secret): string
            {
                return 'v1/' . base64_encode($secret);
            }

            /**
             * Never called.
             *
             * @param  string  $ciphertext
             * @return string
             */
            #[\Override]
            public function decrypt(string $ciphertext): string
            {
                return $ciphertext;
            }
        });

        $stored = $secrets->apply('{"api_secret":"v1/b2xk"}', ['api_secret' => null, 'client_secret' => new Secret(self::SECRET)]);

        self::assertSame('{"client_secret":"v1/' . base64_encode(self::SECRET) . '"}', $stored);
    }

    /**
     * Each secret given is checked in the order the protocol declares them,
     * past one given as `null`, which is never refused; and a client secret is
     * unsupported for an OIDC client that authenticates with `private_key_jwt`,
     * once it is a usable string.
     *
     * @return void
     */
    public function testChecksEachSecretGiven(): void
    {
        $basic = OidcSettings::fromArray(['client_authentication' => 'client_secret_basic']);
        $jwt   = OidcSettings::fromArray(['client_authentication' => 'private_key_jwt']);
        $names = ['api_secret', 'client_secret', 'other_secret'];

        self::assertSame([], ConnectionSecrets::violations($basic, $names, ['api_secret' => null, 'client_secret' => self::SECRET]));
        self::assertSame([], ConnectionSecrets::violations($jwt, $names, ['api_secret' => self::SECRET, 'other_secret' => self::OTHER]));

        $overlong = str_repeat('a', ConnectionSecrets::MAX_LENGTH + 1);

        self::assertSame([
            ['setting' => 'client_secret', 'code' => 'required'],
            ['setting' => 'other_secret', 'code' => 'too_long'],
        ], self::serialized(ConnectionSecrets::violations($basic, $names, ['api_secret' => null, 'client_secret' => '', 'other_secret' => $overlong])));

        $unsupported = ConnectionSecrets::violations($jwt, $names, ['client_secret' => self::SECRET]);
        $empty       = ConnectionSecrets::violations($jwt, $names, ['client_secret' => '']);

        self::assertSame([['setting' => 'client_secret', 'code' => 'unsupported']], self::serialized($unsupported));
        self::assertSame([['setting' => 'client_secret', 'code' => 'required']], self::serialized($empty));
    }

    /**
     * The secrets a change alters are those given as a string and those given
     * as `null` that are stored, in the order the protocol declares them.
     *
     * @return void
     */
    public function testNamesTheSecretsAChangeAlters(): void
    {
        $names = ['unstored', 'given', 'stored', 'absent'];
        $given = ['stored' => null, 'given' => self::SECRET, 'unstored' => null];

        self::assertSame(['given', 'stored'], ConnectionSecrets::changedNames($names, $given, ['stored', 'absent']));
        self::assertSame(['given'], ConnectionSecrets::changedNames($names, $given, []));
    }

    /**
     * An encrypter that cannot encrypt propagates, naming no secret.
     *
     * @return void
     */
    public function testAFailedEncryptionPropagates(): void
    {
        $secrets = new ConnectionSecrets(new class implements SecretEncrypter {
            /**
             * Fail.
             *
             * @param  string  $secret
             * @return string
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function encrypt(#[\SensitiveParameter] string $secret): string
            {
                unset($secret);

                throw new \RuntimeException('The key management service is unavailable.');
            }

            /**
             * Never called.
             *
             * @param  string  $ciphertext
             * @return string
             */
            #[\Override]
            public function decrypt(string $ciphertext): string
            {
                return $ciphertext;
            }
        });

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The key management service is unavailable.');

        $secrets->apply(null, ['client_secret' => new Secret(self::SECRET)]);
    }

    /**
     * Rows of `[column]`: stored secrets that are not an object of ciphertexts
     * by name.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedColumns(): iterable
    {
        yield from [
            'not json'            => ['client_secret=' . self::SECRET],
            'a string'            => ['"' . self::SECRET . '"'],
            'a list'              => ['["' . self::SECRET . '"]'],
            'a number ciphertext' => ['{"client_secret":12}'],
            'an empty ciphertext' => ['{"client_secret":""}'],
            'a nested ciphertext' => ['{"client_secret":{"value":"' . self::SECRET . '"}}'],
        ];
    }

    /**
     * A malformed column is an `UnexpectedValueException` from every read and
     * change, naming neither its content nor a secret.
     *
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideMalformedColumns')]
    public function testRefusesAMalformedColumn(string $column): void
    {
        $secrets    = $this->secrets();
        $connection = self::connection($column);
        $calls      = [
            static fn (): mixed => $secrets->names($connection),
            static fn (): mixed => $secrets->masked($connection, ['client_secret']),
            static fn (): mixed => $secrets->reveal($connection, 'client_secret'),
            static fn (): mixed => $secrets->apply($column, ['client_secret' => null]),
        ];

        foreach ($calls as $call) {

            try {
                $call();
                self::fail('The malformed column was read.');
            } catch (\UnexpectedValueException $exception) {
                self::assertSame('The connection\'s stored secrets are not a JSON object of ciphertexts by name.', $exception->getMessage());
                self::assertStringNotContainsString(self::SECRET, $exception->getMessage());
            }
        }
    }

    /**
     * A secret set is found and revealed, from the row or through the
     * contract; one not set, or a connection that is gone, has none.
     *
     * @return void
     */
    public function testASecretIsReadThroughTheContract(): void
    {
        $secrets    = app(ConnectionSecrets::class);
        $connection = $this->makeConnection(['secrets' => $secrets->apply(null, ['client_secret' => new Secret('the-secret')])]);
        $contract   = new IdentifiedConnection($connection->id);
        $gone       = new IdentifiedConnection('01jbgoneconnection00000000');

        self::assertSame([true, true, false, false], [
            $secrets->isSet($connection, 'client_secret'),
            $secrets->isSet($contract, 'client_secret'),
            $secrets->isSet($contract, 'api_secret'),
            $secrets->isSet($gone, 'client_secret'),
        ]);
        self::assertTrue($secrets->revealFor($connection, 'client_secret')?->equals('the-secret'));
        self::assertTrue($secrets->revealFor($contract, 'client_secret')?->equals('the-secret'));
        self::assertNull($secrets->revealFor($contract, 'api_secret'));
        self::assertNull($secrets->revealFor($gone, 'client_secret'));
        self::assertFalse($secrets->isSet($this->makeConnection(), 'client_secret'));
    }

    /**
     * A row is read as it is given, never again from the table: what it holds
     * unsaved is what is found.
     *
     * @return void
     */
    public function testARowIsReadAsItIsGiven(): void
    {
        $secrets    = app(ConnectionSecrets::class);
        $connection = $this->makeConnection();

        $connection->secrets = $secrets->apply(null, ['client_secret' => new Secret('the-secret')]);

        self::assertTrue($secrets->isSet($connection, 'client_secret'));
        self::assertFalse($secrets->isSet(new IdentifiedConnection($connection->id), 'client_secret'));
    }

    /**
     * The secrets, through the bound encrypter.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSecrets
     */
    private function secrets(): ConnectionSecrets
    {
        $secrets = $this->app?->make(ConnectionSecrets::class);

        self::assertInstanceOf(ConnectionSecrets::class, $secrets);

        return $secrets;
    }

    /**
     * A connection, unsaved, holding the secrets column given.
     *
     * @param  ?string  $secrets
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private static function connection(?string $secrets): Connection
    {
        $connection = new Connection;

        $connection->forceFill(['tenant_id' => 'tenant-1', 'protocol' => 'oidc', 'display_name' => 'Example', 'secrets' => $secrets]);

        return $connection;
    }

    /**
     * An encrypter that encrypts and refuses to decrypt, so a read that
     * decrypts fails.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SecretEncrypter
     */
    private static function refusingToDecrypt(): SecretEncrypter
    {
        return new class implements SecretEncrypter {
            /**
             * A stand-in ciphertext.
             *
             * @param  string  $secret
             * @return string
             */
            #[\Override]
            public function encrypt(#[\SensitiveParameter] string $secret): string
            {
                return base64_encode(strrev($secret));
            }

            /**
             * Refuse.
             *
             * @param  string  $ciphertext
             * @return string
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function decrypt(string $ciphertext): string
            {
                unset($ciphertext);

                throw new \RuntimeException('Decryption was attempted.');
            }
        };
    }

    /**
     * The violations, as they are serialised.
     *
     * @param  list<\SineMacula\Laravel\Sso\Connections\SettingViolation>  $violations
     * @return list<array<string, mixed>>
     */
    private static function serialized(array $violations): array
    {
        return array_map(static fn (SettingViolation $violation): array => $violation->jsonSerialize(), $violations);
    }
}
