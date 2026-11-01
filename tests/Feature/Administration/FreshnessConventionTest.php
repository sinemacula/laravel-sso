<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
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
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests of the convention every change to a connection, a key or a
 * certificate follows (SSO-2.12), disabling, deleting and migrating a
 * connection's subjects included: it asks the freshness contract, with the
 * operation's stable name and its configured maximum age, before it writes.
 * Under the default contract, which refuses everything, each is refused with
 * `freshness_required`, writing and reporting nothing; under one that answers
 * `fresh`, each asks exactly its operations. A change to the display name, the
 * mapping or the scopes asks nothing, and enabling asks even when the
 * connection is enabled already.
 *
 * Each operation's maximum age is set to a value of its own, none the default,
 * so a test shows the age asked with was read for that operation.
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
    use RecordsEventSequences, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The tenant whose connections the helpers act on. */
    private const string TENANT = 'tenant-1';

    /** @var array<string, int> The maximum age configured for each operation a change asks, by its key. */
    private const array MAX_AGES = [
        'connection_trust'         => 111,
        'connection_enable'        => 222,
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

    /** @var \SineMacula\Laravel\Sso\Administration\ActingIdentity Who makes each change. */
    private ActingIdentity $actor;

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
     * Bind a fixed clock, turn the protocols and IdP-initiated sign-in on, give
     * each operation a maximum age of its own, create the tables, and prepare
     * an OIDC connection and a SAML connection with a current and a next key
     * and a trusted certificate, under a contract that answers `fresh`.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->actor = new ActingIdentity('App\Models\User', '42');

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.oidc', true);
        config()->set('sso.features.idp_initiated', true);

        foreach (self::MAX_AGES as $key => $seconds) {
            config()->set('sso.freshness.max_age_seconds.' . $key, $seconds);
        }

        $this->createConnectionTables();
        $this->createDomainsTable();
        $this->createFlowTables();
        $this->prepare();
        $this->startRecordingEvents();
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
        $this->dropDomainsTable();
        $this->dropConnectionTables();

        parent::tearDown();
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
        yield 'disable' => ['disable', [FreshnessOperation::CONNECTION_ENABLE]];
        yield 'delete' => ['delete', [FreshnessOperation::CONNECTION_DELETE]];
        yield 'subject migration' => ['migrate', [FreshnessOperation::CONNECTION_TRUST, FreshnessOperation::LINK_REMOVE]];
        yield 'add next' => ['add next', [FreshnessOperation::KEYS_ROTATE]];
        yield 'make current' => ['make current', [FreshnessOperation::KEYS_ROTATE]];
        yield 'retire' => ['retire', [FreshnessOperation::KEYS_ROTATE]];
        yield 'trust certificate' => ['trust certificate', [FreshnessOperation::CONNECTION_TRUST]];
        yield 'distrust certificate' => ['distrust certificate', [FreshnessOperation::CONNECTION_TRUST]];
    }

    /**
     * Under the default contract, which refuses every operation, the mutation
     * is refused with `freshness_required`: no row is written or changed, and
     * nothing is reported.
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
     * Under a contract that answers `fresh`, the mutation asks exactly its
     * operations, in order, each with the maximum age configured for it, and
     * goes ahead.
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
            static fn (FreshnessOperation $operation): array => ['operation' => $operation, 'max_age_seconds' => self::MAX_AGES[$operation->configKey()]],
            $operations,
        );

        self::assertSame($expected, $freshness->asked());

        foreach ($operations as $operation) {
            $freshness->assertAsked($operation, self::MAX_AGES[$operation->configKey()]);
        }
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
     * An update of the display name, the attribute mapping or the scopes alone
     * asks the contract nothing, and is written and reported.
     *
     * @param  array<string, mixed>  $changes
     * @param  string  $changed
     * @return void
     */
    #[DataProvider('provideChangesAskingNothing')]
    public function testAChangeThatWidensNothingAsksNothing(array $changes, string $changed): void
    {
        $freshness = $this->freshness();
        $result    = $this->connections()->update(self::TENANT, $this->oidc, $changes, $this->actor);

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame([$changed], $result->changedSettings);

        $freshness->assertNotAsked();
    }

    /**
     * Enabling asks `sso.connection.enable` even when the connection is enabled
     * already, which then changes nothing.
     *
     * @return void
     */
    public function testEnablingAsksEvenWhenAlreadyEnabled(): void
    {
        self::assertSame(ConnectionStatus::ENABLED, $this->connections()->enable(self::TENANT, $this->oidc, $this->actor)->status);

        $freshness = $this->freshness();

        self::assertSame(ConnectionStatus::UNCHANGED, $this->connections()->enable(self::TENANT, $this->oidc, $this->actor)->status);

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
     * Each mutation of a connection, by name, to run against the connections
     * prepared.
     *
     * @return array<string, \Closure(): \SineMacula\Laravel\Sso\Connections\ConnectionResult>
     */
    private function connectionMutations(): array
    {
        return [
            'create'               => fn (): ConnectionResult => $this->connections()->create(self::TENANT, 'oidc', 'Second', self::OIDC, actor: $this->actor),
            'update trust setting' => fn (): ConnectionResult => $this->connections()->update(
                self::TENANT,
                $this->oidc,
                ['settings' => ['token_endpoint' => 'https://idp.example.com/oauth/token']],
                $this->actor,
            ),
            'update client secret' => fn (): ConnectionResult => $this->connections()->update(
                self::TENANT,
                $this->oidc,
                ['settings' => ['client_secret' => 'the-rotated-client-secret']],
                $this->actor,
            ),
            'update idp initiated' => fn (): ConnectionResult => $this->connections()->update(
                self::TENANT,
                $this->saml,
                ['settings' => ['idp_initiated' => true, 'idp_initiated_start_url' => 'https://app.example.com/start']],
                $this->actor,
            ),
            'update idp initiated off' => fn (): ConnectionResult => $this->connections()->update(
                self::TENANT,
                $this->samlIdpInitiated,
                ['settings' => ['idp_initiated' => false, 'idp_initiated_start_url' => null]],
                $this->actor,
            ),
            'enable'  => fn (): ConnectionResult => $this->connections()->enable(self::TENANT, $this->oidc, $this->actor),
            'disable' => fn (): ConnectionResult => $this->lifecycle()->disable(self::TENANT, $this->oidc, $this->actor),
            'delete'  => fn (): ConnectionResult => $this->lifecycle()->delete(self::TENANT, $this->oidc, $this->actor),
            'migrate' => fn (): ConnectionResult => $this->migration()->migrate(
                self::TENANT,
                $this->oidc,
                ['settings' => ['issuer' => 'https://login.example.com']],
                [],
                $this->actor,
            ),
        ];
    }

    /**
     * Each change to a key or certificate, by name, to run against the keys
     * prepared.
     *
     * @return array<string, \Closure(): \SineMacula\Laravel\Sso\Keys\KeyResult>
     */
    private function keyMutations(): array
    {
        return [
            'add next'             => fn (): KeyResult => $this->keys()->addNext(self::TENANT, $this->oidc, KeyUse::CLIENT_ASSERTION, KeyType::EC, $this->actor),
            'make current'         => fn (): KeyResult => $this->keys()->makeCurrent(self::TENANT, $this->saml, $this->nextKey, $this->actor),
            'retire'               => fn (): KeyResult => $this->keys()->retire(self::TENANT, $this->saml, $this->nextKey, $this->actor),
            'trust certificate'    => fn (): KeyResult => $this->keys()->trustCertificate(self::TENANT, $this->saml, Certificates::distinct(41), $this->actor),
            'distrust certificate' => fn (): KeyResult => $this->keys()->distrustCertificate(self::TENANT, $this->saml, $this->trustedCertificate, $this->actor),
        ];
    }

    /**
     * Prepare, under a contract that answers `fresh`, an OIDC connection, a
     * SAML connection with a current and a next signing key and a trusted
     * certificate, and a SAML connection with IdP-initiated sign-in on.
     *
     * @return void
     */
    private function prepare(): void
    {
        $this->freshness();

        $oidc = $this->connections()->create(self::TENANT, 'oidc', 'Acme', self::OIDC, actor: $this->actor);
        $saml = $this->connections()->create(self::TENANT, 'saml2', 'Acme', self::SAML, actor: $this->actor);
        $on   = $this->connections()->create(
            self::TENANT,
            'saml2',
            'Started by the IdP',
            self::SAML + ['idp_initiated' => true, 'idp_initiated_start_url' => 'https://app.example.com/start'],
            actor: $this->actor,
        );

        $this->oidc             = (string) $oidc->connection?->id;
        $this->saml             = (string) $saml->connection?->id;
        $this->samlIdpInitiated = (string) $on->connection?->id;

        $this->currentKey         = $this->summary($this->keys()->addNext(self::TENANT, $this->saml, KeyUse::SP_SIGNING, KeyType::EC, $this->actor))->id;
        $this->nextKey            = $this->summary($this->keys()->addNext(self::TENANT, $this->saml, KeyUse::SP_SIGNING, KeyType::EC, $this->actor))->id;
        $this->trustedCertificate = $this->summary($this->keys()->trustCertificate(self::TENANT, $this->saml, Certificates::distinct(40), $this->actor))->id;

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
     * Every row of the connections table and the keys table, as stored, in
     * order of id.
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
