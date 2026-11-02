<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Keys\ClientAssertionKeys;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\ClientAssertionAlgorithm;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Feature tests for the pinned client assertion algorithm (SSO-2.4, RFC 7523):
 * a key and an algorithm that do not fit are refused whichever of them changes,
 * and changing the algorithm is a trust change like any other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClientAssertionKeys::class)]
#[CoversClass(ClientAssertionAlgorithm::class)]
#[CoversClass(ConnectionService::class)]
#[CoversClass(KeyService::class)]
final class ClientAssertionAlgorithmTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The tenant of the connection. */
    private const string TENANT = 'tenant-1';

    /** @var string The setting. */
    private const string SETTING = 'client_assertion_algorithm';

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness What is asked for fresh authentication. */
    private RecordingFreshness $freshness;

    /**
     * Bind a fixed clock and fresh authentication, and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, $this->freshness);

        config()->set('sso.features.oidc', true);

        $this->createConnectionTables();
        $this->createFlowTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * Rows of `[type, allowed, refused]`: what a key of each type signs with.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Keys\Enums\KeyType, 1: list<string>, 2: list<string>}>
     */
    public static function provideTypes(): iterable
    {
        yield 'an RSA key' => [KeyType::RSA, ['PS256', 'RS256'], ['ES256']];
        yield 'a P-256 key' => [KeyType::EC, ['ES256'], ['PS256', 'RS256']];
    }

    /**
     * An RSA key signs with PS256 by default or RS256, a P-256 key with ES256
     * alone, and an unknown algorithm fits nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  list<string>  $allowed
     * @param  list<string>  $refused
     * @return void
     */
    #[DataProvider('provideTypes')]
    public function testEachKeyTypeSignsWithItsOwnAlgorithms(KeyType $type, array $allowed, array $refused): void
    {
        self::assertSame($allowed, ClientAssertionAlgorithm::allowedFor($type));
        self::assertTrue(ClientAssertionAlgorithm::fits(null, $type));

        foreach ($allowed as $algorithm) {
            self::assertTrue(ClientAssertionAlgorithm::fits($algorithm, $type), $algorithm);
        }

        foreach ([...$refused, 'ES384', 'none', ''] as $algorithm) {
            self::assertFalse(ClientAssertionAlgorithm::fits($algorithm, $type), $algorithm);
        }
    }

    /**
     * Rows of `[key state, type, algorithm]`: a current or next key an
     * algorithm does not fit.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Keys\Enums\KeyState, 1: \SineMacula\Laravel\Sso\Keys\Enums\KeyType, 2: string}>
     */
    public static function provideUnfittingKeys(): iterable
    {
        yield 'RS256, a current P-256 key' => [KeyState::CURRENT, KeyType::EC, 'RS256'];
        yield 'PS256, a next P-256 key' => [KeyState::NEXT, KeyType::EC, 'PS256'];
        yield 'ES256, a current RSA key' => [KeyState::CURRENT, KeyType::RSA, 'ES256'];
        yield 'ES256, a next RSA key' => [KeyState::NEXT, KeyType::RSA, 'ES256'];
    }

    /**
     * An algorithm the connection's current or next key cannot sign under is
     * refused as `unsupported`, with nothing written or voided.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  string  $algorithm
     * @return void
     */
    #[DataProvider('provideUnfittingKeys')]
    public function testAnAlgorithmThatDoesNotFitAKeyIsRefused(KeyState $state, KeyType $type, string $algorithm): void
    {
        $connection = $this->connection();

        $this->storeKey($connection, $type, $state);

        $result = $this->update($connection, $algorithm);

        self::assertEquals([new SettingViolation(self::SETTING, ViolationCode::UNSUPPORTED)], $result->violations);
        self::assertArrayNotHasKey(self::SETTING, $connection->refresh()->settings);
        self::assertSame(0, $connection->trust_version);
    }

    /**
     * A retiring key signs nothing, so it does not hold the algorithm back.
     *
     * @return void
     */
    public function testARetiringKeyDoesNotCount(): void
    {
        $connection = $this->connection();

        $this->storeKey($connection, KeyType::EC, KeyState::RETIRING);

        self::assertTrue($this->update($connection, 'RS256')->isSucceeded());
    }

    /**
     * An algorithm that fits is stored and is a trust change: it asks fresh
     * authentication, raises the trust version and voids what is in flight; the
     * same value again changes nothing, and removing it is a change too.
     *
     * @return void
     */
    public function testChangingTheAlgorithmIsATrustChange(): void
    {
        $connection = $this->connection();
        $request    = $this->makeAuthorizationRequest($connection);

        $this->storeKey($connection, KeyType::RSA, KeyState::CURRENT);

        self::assertTrue($this->update($connection, 'RS256')->isSucceeded());

        $connection->refresh();

        self::assertSame('RS256', $connection->settings[self::SETTING]);
        self::assertSame(1, $connection->trust_version);
        self::assertNotNull($request->refresh()->voided_at);
        self::assertContains(FreshnessOperation::CONNECTION_TRUST, array_column($this->freshness->asked(), 0));

        self::assertTrue($this->update($connection, 'RS256')->isSucceeded());
        self::assertSame(1, $connection->refresh()->trust_version);

        self::assertTrue($this->update($connection, null)->isSucceeded());
        self::assertArrayNotHasKey(self::SETTING, $connection->refresh()->settings);
        self::assertSame(2, $connection->trust_version);
    }

    /**
     * With no key yet, any algorithm the package signs with may be saved, and
     * one it does not is refused by the settings' own rule, never the keys'.
     *
     * @return void
     */
    public function testWithNoKeyOnlyTheValueIsJudged(): void
    {
        $connection = $this->connection();

        self::assertTrue($this->update($connection, 'ES256')->isSucceeded());
        self::assertEquals([new SettingViolation(self::SETTING, ViolationCode::NOT_ALLOWED)], $this->update($connection, 'HS256')->violations);
    }

    /**
     * Rows of `[algorithm, type, fits]`: a key added under a pinned algorithm.
     *
     * @return iterable<string, array{0: ?string, 1: \SineMacula\Laravel\Sso\Keys\Enums\KeyType, 2: bool}>
     */
    public static function provideAddedKeys(): iterable
    {
        yield 'none pinned, RSA' => [null, KeyType::RSA, true];
        yield 'none pinned, P-256' => [null, KeyType::EC, true];
        yield 'PS256, RSA' => ['PS256', KeyType::RSA, true];
        yield 'RS256, RSA' => ['RS256', KeyType::RSA, true];
        yield 'ES256, P-256' => ['ES256', KeyType::EC, true];
        yield 'RS256, P-256' => ['RS256', KeyType::EC, false];
        yield 'PS256, P-256' => ['PS256', KeyType::EC, false];
        yield 'ES256, RSA' => ['ES256', KeyType::RSA, false];
    }

    /**
     * A key that does not fit the pinned algorithm is refused before it is
     * generated, naming its type; one that fits is added.
     *
     * @param  ?string  $algorithm
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  bool  $fits
     * @return void
     */
    #[DataProvider('provideAddedKeys')]
    public function testAKeyAddedMustFitThePinnedAlgorithm(?string $algorithm, KeyType $type, bool $fits): void
    {
        $connection = $this->connection($algorithm === null ? [] : [self::SETTING => $algorithm]);
        $result     = app(KeyService::class)->addNext(self::TENANT, $connection->id, KeyUse::CLIENT_ASSERTION, $type);

        self::assertSame($fits, $result->isSucceeded());
        self::assertSame($fits ? 1 : 0, ConnectionKey::query()->where('connection_id', $connection->id)->count());
        self::assertEquals($fits ? [] : [new SettingViolation('key_type', ViolationCode::NOT_ALLOWED)], $result->violations);
    }

    /**
     * An algorithm pinned while a key was being generated is found under the
     * lock, and the key is refused rather than stored.
     *
     * @return void
     */
    public function testAKeyIsJudgedAgainUnderTheLock(): void
    {
        $connection = $this->connection();
        $encrypter  = app(SecretEncrypter::class);

        $this->app?->instance(SecretEncrypter::class, new readonly class ($encrypter, $connection) implements SecretEncrypter {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SecretEncrypter  $encrypter
             * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
             */
            public function __construct(

                /** Encrypts for real. */
                private SecretEncrypter $encrypter,

                /** The connection whose algorithm is pinned meanwhile. */
                private Connection $connection,
            ) {}

            /**
             * Pin the algorithm, then encrypt, as a change racing the key's
             * generation would.
             *
             * @param  string  $plaintext
             * @return string
             */
            #[\Override]
            public function encrypt(#[\SensitiveParameter] string $plaintext): string
            {
                $pinned = ['client_authentication' => 'private_key_jwt', 'client_assertion_algorithm' => 'ES256'];

                Connection::query()->whereKey($this->connection->id)->update(['settings' => json_encode($pinned)]);

                return $this->encrypter->encrypt($plaintext);
            }

            /**
             * Decrypt.
             *
             * @param  string  $ciphertext
             * @return string
             */
            #[\Override]
            public function decrypt(#[\SensitiveParameter] string $ciphertext): string
            {
                return $this->encrypter->decrypt($ciphertext);
            }
        });

        $result = app(KeyService::class)->addNext(self::TENANT, $connection->id, KeyUse::CLIENT_ASSERTION, KeyType::RSA);

        self::assertEquals([new SettingViolation('key_type', ViolationCode::NOT_ALLOWED)], $result->violations);
        self::assertSame(0, ConnectionKey::query()->where('connection_id', $connection->id)->count());
    }

    /**
     * A key of another use is never judged by the setting.
     *
     * @return void
     */
    public function testAnotherUseIsNotJudged(): void
    {
        $connection = $this->connection([self::SETTING => 'ES256']);

        self::assertTrue(ClientAssertionKeys::fits($connection, KeyUse::SP_SIGNING, KeyType::RSA));
    }

    /**
     * The update asked for: the setting changed to the algorithm, or removed.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?string  $algorithm
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     */
    private function update(Connection $connection, ?string $algorithm): ConnectionResult
    {
        return app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => [self::SETTING => $algorithm]]);
    }

    /**
     * An OIDC connection using `private_key_jwt`.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connection(array $settings = []): Connection
    {
        return $this->makeConnection([
            'tenant_id' => self::TENANT,
            'protocol'  => 'oidc',
            'settings'  => ['client_authentication' => 'private_key_jwt', ...$settings],
        ]);
    }

    /**
     * Store a key row of the connection, whose public half is not read here.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @return void
     */
    private function storeKey(Connection $connection, KeyType $type, KeyState $state): void
    {
        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::CLIENT_ASSERTION,
            'state'         => $state,
            'key_type'      => $type,
            'key_bits'      => $type === KeyType::RSA ? 2048 : 256,
            'public_key'    => 'not-read',
            'private_key'   => 'not-read',
            'fingerprint'   => hash('sha256', $state->value . $type->value),
        ])->save();
    }
}
