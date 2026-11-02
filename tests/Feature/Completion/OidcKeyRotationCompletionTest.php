<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Database\Migrations\Migration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionStatus;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\JwksRefreshed;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Metadata\JwksRefetcher;
use SineMacula\Laravel\Sso\Metadata\ProviderKeys;
use SineMacula\Laravel\Sso\Metadata\TransitionReceipts;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for a key rotation found by a callback's own unknown-`kid`
 * refetch (SSO-2.13, SSO-7.3): the refetch commits a JWKS that removes a key,
 * so everything in flight is voided and the trust version raised, except the
 * one sign-in whose token asked, which may finish across exactly that
 * transition once its token has passed every check under the new keys. Every
 * other request and every issued code stays voided; anything else that happens
 * between the refetch and the final locks refuses the sign-in; a request voided
 * by anything else is never restored, and a key only added voids nothing.
 *
 * The order is exact in this process: what happens between the refetch and the
 * locks runs at the UserInfo request, the last provider call before them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwksRefetcher::class)]
#[CoversClass(ProviderKeys::class)]
#[CoversClass(TransitionReceipts::class)]
#[CoversClass(CompletionPipeline::class)]
final class OidcKeyRotationCompletionTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The tenant of the connection. */
    private const string TENANT = 'tenant-1';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The key the provider signs with first, made once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The key the provider rotates to, made once. */
    private static ?FakeSigningKey $next = null;

    /** @var \Tests\Fixtures\FixedClock The clock. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher every request goes through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider. */
    private FakeOpenIdProvider $provider;

    /**
     * Bind a fixed clock, fresh authentication, a limiter that allows every
     * attempt and the fake fetcher, configure the endpoints and the
     * application, and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock    = new FixedClock('2026-11-01T09:30:00Z');
        $this->fetcher  = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(FakeOpenIdProvider::ISSUER, self::key(), $this->clock))->serve($this->fetcher);

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(AttemptLimiter::class, new readonly class implements AttemptLimiter {
            /**
             * Allow every attempt.
             *
             * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
             * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
             */
            #[\Override]
            public function attempt(AttemptSubject $subject): AttemptResult
            {
                unset($subject);

                return AttemptResult::allowed();
            }
        });

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::singleUseMigration()->up(); // @phpstan-ignore method.notFound
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::singleUseMigration()->down(); // @phpstan-ignore method.notFound
        $this->dropDomainsTable();
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * The sign-in whose token triggered the rotation finishes, with a code that
     * stands, its request neither voided nor restored; everything else in
     * flight is voided, the trust version raised once.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheTriggeringSignInFinishesAndEverythingElseIsVoided(): void
    {
        $connection = $this->connection();
        $other      = $this->started($connection)[0];
        $issued     = $this->makeHandoffCode($connection);

        $this->rotate();

        [$trigger, $grant] = $this->started($connection);

        $this->startRecordingEvents();

        $result = $this->complete($connection, $grant);

        self::assertSame(CompletionStatus::COMPLETED, $result->status);
        self::assertNull($result->reason);

        $row = $trigger->fresh();

        self::assertNotNull($row);
        self::assertNull($row->voided_at);
        self::assertNotNull($row->completed_at);
        self::assertSame(0, $row->trust_version);
        self::assertNotNull($other->fresh()?->voided_at);
        self::assertNotNull($issued->fresh()?->voided_at);

        $new = HandoffCode::query()->whereKeyNot($issued->id)->sole();

        self::assertNull($new->voided_at);

        $connection->refresh();

        self::assertSame(1, $connection->trust_version);
        self::assertSame(1, $connection->jwks_version);
        self::assertCount(1, array_filter($this->recordedEvents(), static fn (object $event): bool => $event instanceof JwksRefreshed));
    }

    /**
     * Another request's callback, its request voided by the rotation, is
     * refused at its consumption with no provider call, whatever key signed it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEveryOtherRequestStaysVoided(): void
    {
        $connection = $this->connection();

        [, $otherGrant] = $this->started($connection);

        $this->rotate();

        [, $grant] = $this->started($connection);

        self::assertSame(CompletionStatus::COMPLETED, $this->complete($connection, $grant)->status);

        $tokenRequests = count($this->tokenRequests());
        $refused       = $this->complete($connection, $otherGrant);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $refused->reason);
        self::assertCount($tokenRequests, $this->tokenRequests());
        self::assertSame(1, HandoffCode::query()->count());
    }

    /**
     * A key only added voids nothing and raises nothing: other requests go on
     * as they were.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAPurelyAdditiveRefetchVoidsNothing(): void
    {
        $connection = $this->connection();

        [$other] = $this->started($connection);

        $this->provider->publish(self::next())->signWith(self::next());

        [, $grant] = $this->started($connection);

        self::assertSame(CompletionStatus::COMPLETED, $this->complete($connection, $grant)->status);
        self::assertNull($other->fresh()?->voided_at);
        self::assertSame(0, $connection->refresh()->trust_version);
        self::assertSame(1, $connection->jwks_version);
    }

    /**
     * Rows of `[change]`: what happens between the refetch and the final locks.
     *
     * @return iterable<string, array{0: \Closure(self, \SineMacula\Laravel\Sso\Models\Connection): void}>
     */
    public static function provideInterveningChanges(): iterable
    {
        yield 'a second trust change' => [static function (self $test, Connection $connection): void {
            self::assertTrue(app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['client_secret' => 'the-rotated-secret']])->isChanged());
        }];

        yield 'a distrust' => [static function (self $test, Connection $connection): void {
            self::assertTrue(app(KeyService::class)->distrustCertificate(self::TENANT, $connection->id, $test->trustedCertificate($connection)->id)->isSucceeded());
        }];

        yield 'a disable' => [static function (self $test, Connection $connection): void {
            self::assertTrue(app(ConnectionLifecycle::class)->disable(self::TENANT, $connection->id)->isChanged());
        }];

        yield 'a disable, then an enable' => [static function (self $test, Connection $connection): void {
            self::assertTrue(app(ConnectionLifecycle::class)->disable(self::TENANT, $connection->id)->isChanged());
            self::assertTrue(app(ConnectionService::class)->enable(self::TENANT, $connection->id)->isChanged());
        }];

        yield 'the allow-list changed' => [static function (self $test, Connection $connection): void {
            self::assertTrue(app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['id_token_algorithms' => ['PS256']]])->isChanged());
        }];
    }

    /**
     * Anything independent that happens between the refetch and the final locks
     * refuses the trigger, voids it, and leaves no code: the receipt names one
     * transition and never adopts a later trust version.
     *
     * @param  \Closure(self, \SineMacula\Laravel\Sso\Models\Connection): void  $change
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideInterveningChanges')]
    public function testAnInterveningChangeRefusesTheTrigger(\Closure $change): void
    {
        $connection = $this->connection(['fetch_userinfo' => true]);

        $this->rotate();

        [$trigger, $grant] = $this->started($connection);

        $this->trustCertificate($connection);

        $this->atUserInfo(function () use ($change, $connection): void {
            $change($this, $connection);
        });

        $result = $this->complete($connection, $grant);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $result->reason);
        self::assertSame(0, HandoffCode::query()->count());
        self::assertNotNull($trigger->fresh()?->voided_at);
    }

    /**
     * The connection deleted between the refetch and the locks refuses the
     * trigger, with no code left.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testADeleteBetweenTheRefetchAndTheLocksRefusesTheTrigger(): void
    {
        $connection = $this->connection(['fetch_userinfo' => true]);

        $this->rotate();

        [, $grant] = $this->started($connection);

        $this->atUserInfo(static function () use ($connection): void {
            self::assertTrue(app(ConnectionLifecycle::class)->delete(self::TENANT, $connection->id)->isSucceeded());
        });

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->complete($connection, $grant)->reason);
        self::assertSame(0, HandoffCode::query()->count());
    }

    /**
     * Another write of the keys since, though it raises no trust version,
     * leaves the JWKS version the receipt did not name, and refuses the
     * trigger; it is not voided by that alone, and is finished.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnotherWriteOfTheKeysRefusesTheTrigger(): void
    {
        $connection = $this->connection(['fetch_userinfo' => true]);

        $this->rotate();

        [$trigger, $grant] = $this->started($connection);

        $this->atUserInfo(static function () use ($connection): void {
            Connection::query()->whereKey($connection->id)->increment('jwks_version');
        });

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->complete($connection, $grant)->reason);
        self::assertSame(0, HandoffCode::query()->count());
        self::assertNull($trigger->fresh()?->voided_at);
        self::assertNotNull($trigger->fresh()?->completed_at);
    }

    /**
     * What was fetched passing its stale limit between the refetch and the
     * locks refuses the trigger with `metadata_expired`, as anywhere.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testMetadataExpiringBetweenTheRefetchAndTheLocksRefusesTheTrigger(): void
    {
        $connection = $this->connection(['fetch_userinfo' => true], ['metadata_fetched_at' => $this->clock->now()->subSeconds(2592000 - 1)]);

        $this->rotate();

        [, $grant] = $this->started($connection);

        $this->atUserInfo(function (): void {
            $this->clock->advance(1);
        });

        self::assertSame(FailureReason::METADATA_EXPIRED, $this->complete($connection, $grant)->reason);
        self::assertSame(0, HandoffCode::query()->count());
    }

    /**
     * A request voided independently before the refetch is never restored and
     * never spared, though its own token's refetch then rotates the keys.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARequestVoidedIndependentlyIsNotRestored(): void
    {
        $connection = $this->connection();

        $this->rotate();

        [$trigger, $grant] = $this->started($connection);

        $this->atToken($grant, static function () use ($connection): void {
            self::assertTrue(app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['client_secret' => 'the-rotated-secret']])->isChanged());
        });

        $result = $this->complete($connection, $grant);
        $voided = $trigger->fresh()?->voided_at;

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $result->reason);
        self::assertNotNull($voided);
        self::assertSame(0, HandoffCode::query()->count());
        self::assertSame(2, $connection->refresh()->trust_version);
    }

    /**
     * A token the new keys do not verify, or that fails a claim under them, is
     * refused for that, however the rotation went: the receipt is handed on
     * only once the whole token has passed. The rotation's voiding stands.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenThatFailsUnderTheNewKeysIsRefused(): void
    {
        $connection = $this->connection();
        $other      = $this->started($connection)[0];

        $this->provider->unpublish('rsa-1')->publish(self::next())->signWith(FakeSigningKey::rsa('rsa-2'));

        [$trigger, $grant] = $this->started($connection);

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->complete($connection, $grant)->reason);
        self::assertSame(0, HandoffCode::query()->count());
        self::assertNull($trigger->fresh()?->voided_at);
        self::assertNotNull($trigger->fresh()?->completed_at);
        self::assertNotNull($other->fresh()?->voided_at);
        self::assertSame(1, $connection->refresh()->trust_version);
    }

    /**
     * A sign-in whose token's `kid` is not in what the rotation brought stays
     * refused for its signature.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAKidTheRotationDidNotBringIsRefused(): void
    {
        $connection = $this->connection();

        $this->provider->unpublish('rsa-1')->publish(self::next())->signWith(FakeSigningKey::rsa('rsa-3'));

        [$trigger, $grant] = $this->started($connection);

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->complete($connection, $grant)->reason);
        self::assertSame(0, HandoffCode::query()->count());
        self::assertNull($trigger->fresh()?->voided_at);
        self::assertNotNull($trigger->fresh()?->completed_at);
    }

    /**
     * UserInfo refused after the rotation refuses the sign-in: the receipt
     * never reaches the locks, and the trigger is left finished, its code never
     * issued.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAUserInfoRefusalAfterTheRotationRefuses(): void
    {
        $connection = $this->connection(['fetch_userinfo' => true]);

        $this->rotate();

        [, $grant] = $this->started($connection);

        $this->provider->respond('userinfo', FakeTokenEndpoint::json(500, []));

        self::assertSame(FailureReason::FETCH_FAILED, $this->complete($connection, $grant)->reason);
        self::assertSame(0, HandoffCode::query()->count());
    }

    /**
     * The same callback again is a replay: a receipt lives only for the
     * completion that got it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAReceiptDoesNotOutliveItsCompletion(): void
    {
        $connection = $this->connection();

        $this->rotate();

        [, $grant] = $this->started($connection);

        self::assertSame(CompletionStatus::COMPLETED, $this->complete($connection, $grant)->status);

        $replayed = $this->complete($connection, $grant);

        self::assertSame(CompletionStatus::REJECTED, $replayed->status);
        self::assertSame(FailureReason::REQUEST_UNKNOWN, $replayed->reason);
        self::assertSame(1, HandoffCode::query()->count());
    }

    /**
     * A request started once the rotation has happened goes on under the new
     * trust version with no receipt at all.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARequestStartedAfterTheRotationNeedsNoReceipt(): void
    {
        $connection = $this->connection();

        $this->rotate();

        [, $first] = $this->started($connection);

        self::assertSame(CompletionStatus::COMPLETED, $this->complete($connection, $first)->status);

        [$second, $grant] = $this->started($connection);

        self::assertSame(1, $second->trust_version);
        self::assertSame(CompletionStatus::COMPLETED, $this->complete($connection, $grant)->status);
    }

    /**
     * Find the provider's trusted certificate row, as the distrust names it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    public function trustedCertificate(Connection $connection): ConnectionKey
    {
        return ConnectionKey::query()->where('connection_id', $connection->id)->where('use', KeyUse::IDP_SIGNING->value)->sole();
    }

    /**
     * Rotate the provider: the old key gone, the new one published and signing.
     *
     * @return void
     */
    private function rotate(): void
    {
        $this->provider->unpublish('rsa-1')->publish(self::next())->signWith(self::next());
    }

    /**
     * Give the connection a trusted certificate row to distrust.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function trustCertificate(Connection $connection): void
    {
        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'public_key'    => self::next()->publicKeyPem,
            'fingerprint'   => hash('sha256', self::next()->publicKeyPem),
        ])->save();
    }

    /**
     * Run the closure when the UserInfo request arrives, the last provider call
     * before the locks, then answer as the provider would.
     *
     * @param  \Closure(): void  $between
     * @return void
     */
    private function atUserInfo(\Closure $between): void
    {
        $this->provider->respond('userinfo', static function (FetchRequest $request) use ($between): FetchResult {
            unset($request);

            $between();

            return FakeTokenEndpoint::json(200, ['sub' => FakeOpenIdProvider::SUBJECT]);
        });
    }

    /**
     * Run the closure when the token request arrives, then answer it, so a
     * change lands after the consumption and before the refetch.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization  $grant
     * @param  \Closure(): void  $between
     * @return void
     */
    private function atToken(FakeAuthorization $grant, \Closure $between): void
    {
        $this->provider->respond('token', static function (FetchRequest $request) use ($grant, $between): FetchResult {
            unset($request);

            $between();

            return FakeTokenEndpoint::json(200, ['id_token' => (string) $grant->idToken, 'access_token' => $grant->accessToken, 'token_type' => 'Bearer']);
        });
    }

    /**
     * Start a sign-in through the connection; its request and what the provider
     * granted it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return array{0: \SineMacula\Laravel\Sso\Models\AuthorizationRequest, 1: \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization}
     *
     * @throws \Random\RandomException
     */
    private function started(Connection $connection): array
    {
        $started = app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $connection->id);

        self::assertTrue($started->isStarted());

        return [
            AuthorizationRequest::query()->where('reference', (string) $started->reference?->value)->firstOrFail(),
            $this->provider->authorize((string) $started->navigation?->url()),
        ];
    }

    /**
     * Complete at the connection's callback.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization  $grant
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(Connection $connection, FakeAuthorization $grant): CompletionResult
    {
        return app(CompletionService::class)->callback($connection->id, new CompletionRequest('GET', $grant->query(), []));
    }

    /**
     * The token requests made, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Fetching\FetchRequest>
     */
    private function tokenRequests(): array
    {
        return array_values(array_filter($this->fetcher->requests(), fn (FetchRequest $request): bool => $request->url === $this->provider->endpoint('token')));
    }

    /**
     * An enabled connection of the provider storing its key.
     *
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connection(array $settings = [], array $attributes = []): Connection
    {
        $jwks = (string) json_encode(['keys' => [self::key()->jwk()]]);

        return $this->makeConnection([
            'tenant_id' => self::TENANT,
            'enabled'   => true,
            'jwks'      => ProviderKeySet::read($jwks, AlgorithmAllowList::of(['RS256']), 65536, 50)?->toStored(),
            'secrets'   => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]),
            'settings'  => OidcSettings::fromArray([
                'issuer'                 => $this->provider->issuer,
                'authorization_endpoint' => $this->provider->endpoint('authorization'),
                'token_endpoint'         => $this->provider->endpoint('token'),
                'jwks_uri'               => $this->provider->endpoint('jwks'),
                'userinfo_endpoint'      => $this->provider->endpoint('userinfo'),
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
                ...$settings,
            ])->toArray(),
            ...$attributes,
        ]);
    }

    /**
     * The key the provider signs with first, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa('rsa-1');
    }

    /**
     * The key the provider rotates to, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function next(): FakeSigningKey
    {
        return self::$next ??= FakeSigningKey::rsa('rsa-2');
    }

    /**
     * The shipped migration of the single-use keys.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function singleUseMigration(): Migration
    {
        return require dirname(__DIR__, 3) . self::SINGLE_USE_MIGRATION;
    }
}
