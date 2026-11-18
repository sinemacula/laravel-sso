<?php

declare(strict_types = 1);

namespace Tests\Integration\Secrets;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Secrets\LaravelSecretEncrypter;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests of rotating `app.key` with stored secrets.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LaravelSecretEncrypter::class)]
final class KeyRotationTest extends TestCase
{
    use UsesConnections;

    /** @var string The table the ciphertext is stored in for the test. */
    private const string TABLE = 'secret_rotation_examples';

    /** @var string The key the secret is first encrypted under. */
    private const string KEY_A = 'base64:QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=';

    /** @var string The key it is rotated to. */
    private const string KEY_B = 'base64:QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=';

    /** @var string A secret no output may show. */
    private const string SECRET = 'the-client-secret-value';

    /**
     * A stored secret decrypts while the old key is a previous one, and not
     * once it is dropped.
     *
     * @return void
     */
    public function testAStoredSecretSurvivesRotationWhileTheOldKeyIsPrevious(): void
    {
        Schema::dropIfExists(self::TABLE);
        Schema::create(self::TABLE, static function (Blueprint $table): void {
            $table->id();
            $table->text('ciphertext');
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::dropIfExists(self::TABLE);
        });

        $this->useKeys(self::KEY_A, []);

        DB::table(self::TABLE)->insert(['ciphertext' => $this->encrypter()->encrypt(self::SECRET)]);

        $stored = DB::table(self::TABLE)->value('ciphertext');

        self::assertIsString($stored);
        self::assertStringNotContainsString(self::SECRET, $stored);

        $this->useKeys(self::KEY_B, [self::KEY_A]);

        self::assertSame(self::SECRET, $this->encrypter()->decrypt($stored));
        self::assertSame(self::SECRET, $this->encrypter()->decrypt($this->encrypter()->encrypt(self::SECRET)));

        $this->useKeys(self::KEY_B, []);

        try {
            $this->encrypter()->decrypt($stored);

            self::fail('Expected a ciphertext under a key no longer listed to be refused.');
        } catch (DecryptException $exception) {
            self::assertStringNotContainsString(self::SECRET, $exception->getMessage());
        }
    }

    /**
     * A secret encrypted after rotation is under the new key.
     *
     * @return void
     */
    public function testANewSecretIsEncryptedUnderTheNewKey(): void
    {
        $this->useKeys(self::KEY_B, [self::KEY_A]);

        $ciphertext = $this->encrypter()->encrypt(self::SECRET);

        $this->useKeys(self::KEY_A, []);

        $this->expectException(\RuntimeException::class);

        $this->encrypter()->decrypt($ciphertext);
    }

    /**
     * A request and a code written under the old key complete and redeem while
     * it is a previous key; once it is dropped, such a code is a server error
     * and stays unredeemed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFlowInFlightSurvivesRotationWhileTheOldKeyIsPrevious(): void
    {
        $this->useKeys(self::KEY_A, []);

        $clock    = new FixedClock('2026-11-01T09:30:00Z');
        $fetcher  = new FakeFetcher;
        $provider = (new FakeOpenIdProvider(clock: $clock))->serve($fetcher);

        $this->app?->instance(Clock::class, $clock);
        $this->app?->instance(Fetcher::class, $fetcher);

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->usePackageTables();

        $connection = $this->makeConnection([
            'enabled'  => true,
            'secrets'  => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]),
            'settings' => [
                'issuer'                 => $provider->issuer,
                'authorization_endpoint' => $provider->endpoint('authorization'),
                'token_endpoint'         => $provider->endpoint('token'),
                'jwks_uri'               => $provider->endpoint('jwks'),
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
            ],
        ]);

        $inFlight    = $this->startAt($connection);
        $issued      = $this->startAt($connection);
        $dropped     = $this->startAt($connection);
        $issuedCode  = $this->completeAt($connection, $provider, $issued);
        $droppedCode = $this->completeAt($connection, $provider, $dropped);

        $this->useKeys(self::KEY_B, [self::KEY_A]);

        $completed = $this->completeAt($connection, $provider, $inFlight);

        self::assertTrue($completed->isCompleted());
        self::assertTrue($this->redeemAt($connection, $issuedCode, $issued)->isRedeemed());

        $this->useKeys(self::KEY_B, []);

        self::assertTrue($this->redeemAt($connection, $completed, $inFlight)->isRedeemed());

        try {
            $this->redeemAt($connection, $droppedCode, $dropped);

            self::fail('Expected a code written under a key no longer listed to be a server error.');
        } catch (DecryptException) {
            self::assertNull(HandoffCode::query()->where('request_reference', $dropped->reference?->value)->sole()->redeemed_at);
        }
    }

    /**
     * Start a `sign_in` for `web` through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function startAt(Connection $connection): StartResult
    {
        $start = app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $connection->id, Clients::browser());

        self::assertTrue($start->isStarted());

        return $start;
    }

    /**
     * Have the provider answer the start and complete it at the callback.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \Random\RandomException
     */
    private function completeAt(Connection $connection, FakeOpenIdProvider $provider, StartResult $start): CompletionResult
    {
        $request = new CompletionRequest('GET', $provider->authorize($start)->query(), []);

        return app(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $connection->id, $request, Clients::browser());
    }

    /**
     * Redeem the completion's code as a `sign_in` with the start's verifier.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    private function redeemAt(Connection $connection, CompletionResult $completion, StartResult $start): RedemptionResult
    {
        $code     = (string) $completion->handoff?->code->reveal();
        $verifier = (string) $start->verifier?->reveal();

        return DB::connection(StorageConnection::name())->transaction(
            static fn (): RedemptionResult => app(HandoffRedemption::class)->redeem(Purpose::SIGN_IN, 'web', $connection->id, $code, $verifier, Clients::browser()),
        );
    }

    /**
     * Set the application key and previous keys, and forget the resolved
     * encrypters.
     *
     * @param  string  $key
     * @param  list<string>  $previous
     * @return void
     */
    private function useKeys(string $key, array $previous): void
    {
        config()->set('app.key', $key);
        config()->set('app.previous_keys', $previous);

        $this->app?->forgetInstance('encrypter');
        $this->app?->forgetScopedInstances();
    }

    /**
     * The bound secret encrypter, the default.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SecretEncrypter
     */
    private function encrypter(): SecretEncrypter
    {
        /** @var \SineMacula\Laravel\Sso\Contracts\SecretEncrypter $encrypter */
        $encrypter = $this->app?->make(SecretEncrypter::class);

        self::assertInstanceOf(LaravelSecretEncrypter::class, $encrypter);

        return $encrypter;
    }
}
