<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\SubjectMigration;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsEventSequences;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for the freshness check every connection, key and certificate
 * change makes before it writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionService::class)]
#[CoversClass(KeyService::class)]
#[CoversClass(ConnectionLifecycle::class)]
#[CoversClass(SubjectMigration::class)]
#[CoversClass(FreshnessGate::class)]
final class FreshnessConventionTest extends TestCase
{
    use RecordsEventSequences;

    /** @var string The tenant whose connections the helpers act on. */
    private const string TENANT = 'tenant-1';

    /** @var array<string, int> The maximum age configured for each operation a change asks, by its key. */
    private const array MAX_AGES = [
        'connection_trust'         => 111,
        'connection_enable'        => 222,
        'connection_disable'       => 777,
        'connection_idp_initiated' => 333,
        'keys_rotate'              => 444,
        'connection_delete'        => 555,
        'link_remove'              => 666,
    ];

    /** @var array<string, string> The settings of a complete OIDC connection. */
    private const array OIDC = [
        'issuer'                 => 'https://idp.example.com',
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => 'https://idp.example.com/token',
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
        'client_secret'          => 'the-client-secret-value',
    ];

    /** @var array<string, string> The settings of a complete SAML connection. */
    private const array SAML = [
        'idp_entity_id' => 'https://idp.example.com/entity',
        'sso_url'       => 'https://idp.example.com/sso',
    ];

    /** @var \SineMacula\Laravel\Sso\Identities\Caller Who makes each change. */
    private Caller $actor;

    /** @var string The OIDC connection. */
    private string $oidc;

    /** @var string The SAML connection. */
    private string $saml;

    /** @var string A SAML connection with IdP-initiated sign-in on. */
    private string $samlIdpInitiated;

    /** @var string The SAML connection's current signing key. */
    private string $currentKey;

    /** @var string The SAML connection's next signing key. */
    private string $nextKey;

    /** @var string The identity provider certificate the SAML connection trusts. */
    private string $trustedCertificate;

    /**
     * Bind a fixed clock, enable the protocols, give each operation its own
     * maximum age and prepare the connections.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->actor = new Caller(new IdentityReference('App\Models\User', '42'), 'session-1');

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.oidc', true);
        config()->set('sso.features.idp_initiated', true);
        config()->set('sso.mapping.custom_attributes', ['department']);

        foreach (self::MAX_AGES as $key => $seconds) {
            config()->set('sso.freshness.max_age_seconds.' . $key, $seconds);
        }

        $this->usePackageTables();
        $this->prepare();
        $this->startRecordingEvents();
    }

    /**
     * Every change to a connection, a key or a certificate, with the operations
     * it asks about, in order.
     *
     * @return iterable<string, array{0: string, 1: list<\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation>}>
     */
    public static function provideMutations(): iterable
    {
        yield 'create' => ['create', [FreshnessOperation::CONNECTION_TRUST]];
        yield 'update of a trust setting' => ['update trust setting', [FreshnessOperation::CONNECTION_TRUST]];
        yield 'update of the client secret' => ['update client secret', [FreshnessOperation::CONNECTION_TRUST]];
        yield 'update turning IdP-initiated sign-in on' => ['update idp initiated', [FreshnessOperation::CONNECTION_IDP_INITIATED]];
        yield 'update turning IdP-initiated sign-in off' => ['update idp initiated off', [FreshnessOperation::CONNECTION_IDP_INITIATED]];
        yield 'enable' => ['enable', [FreshnessOperation::CONNECTION_ENABLE]];
        yield 'disable' => ['disable', [FreshnessOperation::CONNECTION_DISABLE]];
        yield 'delete' => ['delete', [FreshnessOperation::CONNECTION_DELETE]];
        yield 'subject migration' => ['migrate', [FreshnessOperation::CONNECTION_TRUST, FreshnessOperation::LINK_REMOVE]];
        yield 'add next' => ['add next', [FreshnessOperation::KEYS_ROTATE]];
        yield 'make current' => ['make current', [FreshnessOperation::KEYS_ROTATE]];
        yield 'retire' => ['retire', [FreshnessOperation::KEYS_ROTATE]];
        yield 'trust certificate' => ['trust certificate', [FreshnessOperation::CONNECTION_TRUST]];
        yield 'distrust certificate' => ['distrust certificate', [FreshnessOperation::CONNECTION_TRUST]];
    }

    /**
     * Under the default contract each change is refused with nothing written or
     * reported.
     *
     * @param  string  $mutation
     * @param  list<\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation>  $operations
     * @return void
     */
    #[DataProvider('provideMutations')]
    public function testTheDefaultContractRefusesWithNothingWritten(string $mutation, array $operations): void
    {
        self::assertNotSame([], $operations);

        $this->app?->forgetInstance(Freshness::class);

        self::assertInstanceOf(RefusingFreshness::class, $this->app?->make(Freshness::class));

        $before = $this->rows();
        $result = $this->mutate($mutation);

        self::assertFalse($result->isSucceeded());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertSame($before, $this->rows());
        $this->assertNoEvents();
    }

    /**
     * A fresh caller is asked exactly the change's operations with their
     * maximum ages.
     *
     * @param  string  $mutation
     * @param  list<\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation>  $operations
     * @return void
     */
    #[DataProvider('provideMutations')]
    public function testAFreshCallerIsAskedExactlyItsOperations(string $mutation, array $operations): void
    {
        $freshness = $this->freshness();
        $result    = $this->mutate($mutation);

        self::assertTrue($result->isSucceeded());

        $freshness->assertAskedExactly($operations);

        $expected = array_map(
            fn (FreshnessOperation $operation): array => ['operation' => $operation, 'max_age_seconds' => self::MAX_AGES[$operation->configKey()], 'caller' => $this->actor],
            $operations,
        );

        self::assertSame($expected, $freshness->asked());

        foreach ($operations as $operation) {
            $freshness->assertAsked($operation, self::MAX_AGES[$operation->configKey()]);
        }
    }

    /**
     * The caller asked about is the acting identity the event names.
     *
     * @return void
     */
    public function testTheCallerAskedAboutIsTheOneTheEventNames(): void
    {
        $freshness = $this->freshness();

        $this->startRecordingEvents();

        self::assertTrue($this->mutate('update trust setting')->isSucceeded());

        $context = $this->recordedEvents()[0]->context();

        self::assertSame([$this->actor], array_column($freshness->asked(), 'caller'));
        self::assertSame(['App\Models\User', '42'], [$context->actingIdentityMorphClass, $context->actingIdentityId]);
        self::assertNull($context->sessionId);
    }

    /**
     * The changes that never widen or redirect access.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideChangesAskingNothing(): iterable
    {
        yield 'display name' => [['display_name' => 'Renamed'], 'display_name'];
        yield 'attribute mapping' => [['attribute_mapping' => ['department' => 'dept']], 'attribute_mapping'];
        yield 'scopes' => [['settings' => ['scopes' => ['openid', 'email']]], 'scopes'];
    }

    /**
     * A change to the display name, the mapping or the scopes asks nothing.
     *
     * @param  array<string, mixed>  $changes
     * @param  string  $changed
     * @return void
     */
    #[DataProvider('provideChangesAskingNothing')]
    public function testAChangeThatWidensNothingAsksNothing(array $changes, string $changed): void
    {
        $freshness = $this->freshness();
        $result    = $this->connections()->update(self::TENANT, $this->oidc, $changes, Clients::browser(), $this->actor);

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame([$changed], $result->changedSettings);

        $freshness->assertNotAsked();
    }

    /**
     * Enabling asks even when the connection is enabled already.
     *
     * @return void
     */
    public function testEnablingAsksEvenWhenAlreadyEnabled(): void
    {
        self::assertSame(ConnectionStatus::ENABLED, $this->connections()->enable(self::TENANT, $this->oidc, Clients::browser(), $this->actor)->status);

        $freshness = $this->freshness();

        self::assertSame(ConnectionStatus::UNCHANGED, $this->connections()->enable(self::TENANT, $this->oidc, Clients::browser(), $this->actor)->status);

        $freshness->assertAskedExactly([FreshnessOperation::CONNECTION_ENABLE]);
        $freshness->assertAsked(FreshnessOperation::CONNECTION_ENABLE, self::MAX_AGES['connection_enable']);
    }

    /**
     * Run the mutation against the connections and keys prepared.
     *
     * @param  string  $mutation
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult|\SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \LogicException
     */
    private function mutate(string $mutation): ConnectionResult|KeyResult
    {
        $mutations = [...$this->connectionMutations(), ...$this->keyMutations()];

        if (!array_key_exists($mutation, $mutations)) {
            throw new \LogicException(sprintf('No mutation [%s].', $mutation));
        }

        return $mutations[$mutation]();
    }

    /**
     * Each connection mutation, by name.
     *
     * @return array<string, \Closure(): \SineMacula\Laravel\Sso\Connections\ConnectionResult>
     */
    private function connectionMutations(): array
    {
        return [
            'create'               => fn (): ConnectionResult => $this->connections()->create(self::TENANT, 'oidc', 'Second', Clients::browser(), self::OIDC, caller: $this->actor),
            'update trust setting' => fn (): ConnectionResult => $this->connections()->update(
                self::TENANT,
                $this->oidc,
                ['settings' => ['token_endpoint' => 'https://idp.example.com/oauth/token']],
                Clients::browser(),
                $this->actor,
            ),
            'update client secret' => fn (): ConnectionResult => $this->connections()->update(
                self::TENANT,
                $this->oidc,
                ['settings' => ['client_secret' => 'the-rotated-client-secret']],
                Clients::browser(),
                $this->actor,
            ),
            'update idp initiated' => fn (): ConnectionResult => $this->connections()->update(
                self::TENANT,
                $this->saml,
                ['settings' => ['idp_initiated' => true, 'idp_initiated_start_url' => 'https://app.example.com/start']],
                Clients::browser(),
                $this->actor,
            ),
            'update idp initiated off' => fn (): ConnectionResult => $this->connections()->update(
                self::TENANT,
                $this->samlIdpInitiated,
                ['settings' => ['idp_initiated' => false, 'idp_initiated_start_url' => null]],
                Clients::browser(),
                $this->actor,
            ),
            'enable'  => fn (): ConnectionResult => $this->connections()->enable(self::TENANT, $this->oidc, Clients::browser(), $this->actor),
            'disable' => fn (): ConnectionResult => $this->lifecycle()->disable(self::TENANT, $this->oidc, Clients::browser(), $this->actor),
            'delete'  => fn (): ConnectionResult => $this->lifecycle()->delete(self::TENANT, $this->oidc, Clients::browser(), $this->actor),
            'migrate' => fn (): ConnectionResult => $this->migration()->migrate(
                self::TENANT,
                $this->oidc,
                ['settings' => ['issuer' => 'https://login.example.com']],
                [],
                [],
                Clients::browser(),
                $this->actor,
            ),
        ];
    }

    /**
     * Each key or certificate change, by name.
     *
     * @return array<string, \Closure(): \SineMacula\Laravel\Sso\Keys\KeyResult>
     */
    private function keyMutations(): array
    {
        return [
            'add next' => fn (): KeyResult => $this->keys()->addNext(
                self::TENANT,
                $this->oidc,
                KeyUse::CLIENT_ASSERTION,
                Clients::browser(),
                KeyType::EC,
                $this->actor,
            ),
            'make current'         => fn (): KeyResult => $this->keys()->makeCurrent(self::TENANT, $this->saml, $this->nextKey, Clients::browser(), $this->actor),
            'retire'               => fn (): KeyResult => $this->keys()->retire(self::TENANT, $this->saml, $this->nextKey, Clients::browser(), $this->actor),
            'trust certificate'    => fn (): KeyResult => $this->keys()->trustCertificate(self::TENANT, $this->saml, Certificates::distinct(41), Clients::browser(), $this->actor),
            'distrust certificate' => fn (): KeyResult => $this->keys()->distrustCertificate(
                self::TENANT,
                $this->saml,
                $this->trustedCertificate,
                Clients::browser(),
                $this->actor,
            ),
        ];
    }

    /**
     * Prepare an OIDC connection, a SAML connection with keys and a
     * certificate, and an IdP-initiated one.
     *
     * @return void
     */
    private function prepare(): void
    {
        $this->freshness();

        $oidc = $this->connections()->create(self::TENANT, 'oidc', 'Acme', Clients::browser(), self::OIDC, caller: $this->actor);
        $saml = $this->connections()->create(self::TENANT, 'saml2', 'Acme', Clients::browser(), self::SAML, caller: $this->actor);
        $on   = $this->connections()->create(
            self::TENANT,
            'saml2',
            'Started by the IdP',
            Clients::browser(),
            self::SAML + ['idp_initiated' => true, 'idp_initiated_start_url' => 'https://app.example.com/start'],
            caller: $this->actor,
        );

        $this->oidc             = (string) $oidc->connection?->id;
        $this->saml             = (string) $saml->connection?->id;
        $this->samlIdpInitiated = (string) $on->connection?->id;

        $this->currentKey         = $this->summary($this->keys()->addNext(self::TENANT, $this->saml, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA, $this->actor))->id;
        $this->nextKey            = $this->summary($this->keys()->addNext(self::TENANT, $this->saml, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA, $this->actor))->id;
        $this->trustedCertificate = $this->summary($this->keys()->trustCertificate(self::TENANT, $this->saml, Certificates::distinct(40), Clients::browser(), $this->actor))->id;

        self::assertNotSame($this->currentKey, $this->nextKey);
    }

    /**
     * Bind a new contract that answers `fresh`, and return it.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeFreshness
     */
    private function freshness(): FakeFreshness
    {
        $freshness = FakeFreshness::fresh();

        $this->app?->instance(Freshness::class, $freshness);

        return $freshness;
    }

    /**
     * Every row of the connections and keys tables, in id order.
     *
     * @return array{connections: list<array<array-key, mixed>>, keys: list<array<array-key, mixed>>}
     */
    private function rows(): array
    {
        $database = DB::connection(StorageConnection::name());
        $rows     = static fn (string $table): array => array_values(array_map(
            static fn (object $row): array => (array) $row,
            $database->table(StorageConnection::table($table))->orderBy('id')->get()->all(),
        ));

        return ['connections' => $rows('connections.table'), 'keys' => $rows('keys.table')];
    }

    /**
     * The summary a key result carries, which it must.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyResult  $result
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private function summary(KeyResult $result): KeySummary
    {
        self::assertInstanceOf(KeySummary::class, $result->key);

        return $result->key;
    }

    /**
     * The connection helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function connections(): ConnectionService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ConnectionService::class);
    }

    /**
     * The disabling and deleting helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionLifecycle
     */
    private function lifecycle(): ConnectionLifecycle
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ConnectionLifecycle::class);
    }

    /**
     * The subject migration helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Connections\SubjectMigration
     */
    private function migration(): SubjectMigration
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(SubjectMigration::class);
    }

    /**
     * The key helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyService
     */
    private function keys(): KeyService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(KeyService::class);
    }
}
