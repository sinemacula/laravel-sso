<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Domains\DomainWithdrawal;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesEnforcement;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Domains\RecordingWithdrawal;
use Tests\Fixtures\Enforcement\RecordingRevocation;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Feature tests for disabling and deleting a connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionLifecycle::class)]
#[CoversClass(InFlightVoider::class)]
#[CoversClass(ConnectionResult::class)]
final class ConnectionLifecycleTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesDomains, UsesEnforcement, UsesFlowTables;

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string Another tenant. */
    private const string OTHER_TENANT = 'tenant-2';

    /** @var string When the change voids what is in flight, a minute after the rows were made. */
    private const string VOIDED = '2026-11-01T09:31:00+00:00';

    /** @var string When a request or code was voided before the change. */
    private const string EARLIER = '2026-11-01T09:00:00+00:00';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the helpers ask. */
    private RecordingFreshness $freshness;

    /** @var \Tests\Fixtures\Enforcement\RecordingRevocation The revocation contract the helpers call. */
    private RecordingRevocation $revocation;

    /** @var \Tests\Fixtures\Domains\RecordingWithdrawal The domain withdrawal a deletion calls. */
    private RecordingWithdrawal $withdrawal;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The tenant's enabled connection. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\Connection Another enabled connection of the tenant, whose rows stay. */
    private Connection $other;

    /**
     * Bind a fixed clock, freshness, revocation and domain withdrawal, and seed
     * two connections.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock      = new FixedClock('2026-11-01T09:30:00Z');
        $this->freshness  = new RecordingFreshness;
        $this->revocation = new RecordingRevocation;
        $this->withdrawal = new RecordingWithdrawal;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, $this->freshness);
        $this->app?->instance(SessionRevocation::class, $this->revocation);
        $this->app?->instance(DomainWithdrawal::class, $this->withdrawal);

        config()->set('sso.features.oidc', true);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['enabled' => true]);
        $this->other      = $this->makeConnection(['enabled' => true]);

        $this->startRecordingEvents();
    }

    /**
     * Disabling voids only what is in flight, keeps the rest and revokes
     * sessions inside the transaction.
     *
     * @return void
     */
    public function testDisablesAConnection(): void
    {
        $rows   = $this->populate($this->connection);
        $others = $this->populate($this->other);

        $this->clock->advance(60);

        $result = $this->lifecycle()->disable(self::TENANT, $this->connection->id, Clients::browser(), new Caller(new IdentityReference('App\Models\User', '42')));

        $summary = $result->connection;

        self::assertSame(ConnectionStatus::DISABLED, $result->status);
        self::assertTrue($result->isChanged());
        self::assertNotNull($summary);
        self::assertSame($this->connection->id, $summary->id);
        self::assertFalse($summary->enabled);
        self::assertFalse($summary->usable);

        self::assertFalse($this->reread($this->connection)->enabled);
        self::assertTrue($this->reread($this->other)->enabled);
        self::assertSame([[FreshnessOperation::CONNECTION_DISABLE, 300]], $this->freshness->asked());

        self::assertSame([
            $rows['pending']    => self::VOIDED,
            $rows['consumed']   => self::VOIDED,
            $rows['finished']   => null,
            $rows['voided']     => self::EARLIER,
            $others['pending']  => null,
            $others['consumed'] => null,
            $others['finished'] => null,
            $others['voided']   => self::EARLIER,
        ], self::requestsVoided());

        self::assertSame([
            $rows['unredeemed']   => self::VOIDED,
            $rows['redeemed']     => null,
            $rows['voidedCode']   => self::EARLIER,
            $others['unredeemed'] => null,
            $others['redeemed']   => null,
            $others['voidedCode'] => self::EARLIER,
        ], self::codesVoided());

        self::assertSame(self::VOIDED, AuthorizationRequest::query()->findOrFail($rows['consumed'])->updated_at->toIso8601String());
        self::assertSame(self::VOIDED, HandoffCode::query()->findOrFail($rows['unredeemed'])->updated_at->toIso8601String());
        self::assertSame(self::counts(2, 4, 3, 1, 1), $this->countsOf($this->connection));
        self::assertSame(self::counts(2, 4, 3, 1, 1), $this->countsOf($this->other));
        self::assertSame([], $this->withdrawal->calls->getArrayCopy());

        $this->assertRevoked(RevocationReason::CONNECTION_DISABLED);
        $this->assertEventSequence([ConnectionDisabled::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(ConnectionDisabled::class, $event);
        self::assertSame($this->connection->id, $event->context->connectionId);
        self::assertSame(self::TENANT, $event->context->connectionTenantId);
        self::assertSame('oidc', $event->context->protocol);
        self::assertSame('App\Models\User', $event->context->actingIdentityMorphClass);
        self::assertSame('42', $event->context->actingIdentityId);
    }

    /**
     * Disabling a disabled connection asks freshness, then answers `unchanged`
     * and does nothing.
     *
     * @return void
     */
    public function testDisablingADisabledConnectionIsUnchanged(): void
    {
        $this->connection->forceFill(['enabled' => false])->save();

        $request = $this->makeAuthorizationRequest($this->connection);
        $result  = $this->lifecycle()->disable(self::TENANT, $this->connection->id, Clients::browser());

        $summary = $result->connection;

        self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
        self::assertTrue($result->isSucceeded());
        self::assertFalse($result->isChanged());
        self::assertNotNull($summary);
        self::assertSame($this->connection->id, $summary->id);
        self::assertFalse($summary->enabled);
        self::assertSame([[FreshnessOperation::CONNECTION_DISABLE, 300]], $this->freshness->asked());
        self::assertNull(AuthorizationRequest::query()->findOrFail($request->id)->voided_at);
        self::assertSame([], $this->revocation->calls());
        $this->assertNoEvents();
    }

    /**
     * A connection disabled between the first read and the lock is `unchanged`.
     *
     * @return void
     */
    public function testAConnectionDisabledMeanwhileIsUnchanged(): void
    {
        $request = $this->makeAuthorizationRequest($this->connection);

        $this->beforeTheNextTransaction(fn (): mixed => Connection::query()->whereKey($this->connection->id)->update(['enabled' => false]));

        $result = $this->lifecycle()->disable(self::TENANT, $this->connection->id, Clients::browser());

        self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
        self::assertNull(AuthorizationRequest::query()->findOrFail($request->id)->voided_at);
        self::assertSame([], $this->revocation->calls());
        $this->assertNoEvents();
    }

    /**
     * A connection deleted between the first read and the lock is not found.
     *
     * @return void
     */
    public function testAConnectionDeletedMeanwhileIsNotFound(): void
    {
        foreach ($this->changes() as $name => $change) {

            $connection = $this->makeConnection(['enabled' => true]);

            $this->beforeTheNextTransaction(static fn (): mixed => Connection::query()->whereKey($connection->id)->delete());

            self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $change(self::TENANT, $connection->id)->reason, $name);
        }

        self::assertSame([], $this->revocation->calls());
        self::assertSame([], $this->withdrawal->calls->getArrayCopy());
        $this->assertNoEvents();
    }

    /**
     * Removing the last connection that satisfies enforcement keeps the rule,
     * which then fails closed.
     *
     * @param  string  $change
     * @param  \SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus  $status
     * @param  \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason  $reason
     * @return void
     */
    #[TestWith(['disable', ConnectionStatus::DISABLED, RevocationReason::CONNECTION_DISABLED])]
    #[TestWith(['delete', ConnectionStatus::DELETED, RevocationReason::CONNECTION_DELETED])]
    public function testTheLastSatisfyingConnectionGoesAndTheRuleStays(string $change, ConnectionStatus $status, RevocationReason $reason): void
    {
        config()->set('sso.features.enforcement', true);

        $rule = $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$this->connection->id]]);

        self::assertTrue(app(Enforcement::class)->policy(self::TENANT, 'web')->isSatisfiedBy($this->connection->id));

        $result = $this->changes()[$change](self::TENANT, $this->connection->id);
        $policy = app(Enforcement::class)->policy(self::TENANT, 'web');
        $stored = TenantEnforcement::query()->where('tenant_id', self::TENANT)->sole();

        self::assertSame($status, $result->status);
        self::assertSame([true, [$this->connection->id], $rule->version], [$stored->enabled, $stored->connection_ids, $stored->version]);
        self::assertSame([true, [], self::policyVersion($rule->version)], [$policy->isRequired(), $policy->connectionIds, $policy->version]);
        self::assertNotSame(self::policyVersion($rule->version, [$this->connection->id]), $policy->version);
        self::assertFalse($policy->isSatisfiedBy($this->connection->id));
        self::assertFalse($policy->isSatisfiedBy($this->other->id));

        $this->assertRevoked($reason);
    }

    /**
     * A stale caller is refused with `freshness_required` and nothing is
     * written, voided or revoked.
     *
     * @return void
     */
    public function testRefusesAStaleCaller(): void
    {
        $rows = $this->populate($this->connection);

        $this->freshness->answer(FreshnessOutcome::STALE);

        $disabled = $this->lifecycle()->disable(self::TENANT, $this->connection->id, Clients::browser());
        $deleted  = $this->lifecycle()->delete(self::TENANT, $this->connection->id, Clients::browser());

        self::assertTrue($disabled->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $disabled->reason);
        self::assertTrue($deleted->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $deleted->reason);
        self::assertSame([[FreshnessOperation::CONNECTION_DISABLE, 300], [FreshnessOperation::CONNECTION_DELETE, 300]], $this->freshness->asked());

        self::assertTrue($this->reread($this->connection)->enabled);
        self::assertNull(AuthorizationRequest::query()->findOrFail($rows['pending'])->voided_at);
        self::assertNull(HandoffCode::query()->findOrFail($rows['unredeemed'])->voided_at);
        self::assertSame(self::counts(2, 4, 3, 1, 1), $this->countsOf($this->connection));
        self::assertSame([], $this->revocation->calls());
        self::assertSame([], $this->withdrawal->calls->getArrayCopy());
        $this->assertNoEvents();
    }

    /**
     * Another tenant's connection, and an unknown id, are not found before
     * freshness is asked.
     *
     * @return void
     */
    public function testAnotherTenantsConnectionIsNotFound(): void
    {
        $theirs = $this->makeConnection(['tenant_id' => self::OTHER_TENANT, 'enabled' => true]);

        foreach ([[self::TENANT, $theirs->id], [self::OTHER_TENANT, $this->connection->id], [self::TENANT, '01jbunknownconnection00000']] as [$tenant, $id]) {
            self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $this->lifecycle()->disable($tenant, $id, Clients::browser())->reason);
            self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $this->lifecycle()->delete($tenant, $id, Clients::browser())->reason);
        }

        self::assertSame([], $this->freshness->asked());
        self::assertTrue($this->reread($theirs)->enabled);
        self::assertTrue($this->reread($this->connection)->enabled);
        self::assertSame([], $this->revocation->calls());
        $this->assertNoEvents();
    }

    /**
     * An empty or overlong tenant id is the application's mistake.
     *
     * @return void
     */
    public function testRefusesAMalformedTenantId(): void
    {
        foreach ($this->changes() as $change) {

            foreach (['', str_repeat('t', 256)] as $tenant) {

                try {
                    $change($tenant, $this->connection->id);
                    self::fail('A malformed tenant id was accepted.');
                } catch (\InvalidArgumentException $exception) {
                    self::assertSame('A tenant id is 1 to 255 bytes.', $exception->getMessage());
                }
            }
        }

        self::assertSame([], $this->freshness->asked());
    }

    /**
     * A connection whose protocol is no longer registered can still be disabled
     * and deleted.
     *
     * @return void
     */
    public function testAConnectionOfAnUnavailableProtocolCanBeDisabledAndDeleted(): void
    {
        $connection = $this->makeConnection(['protocol' => 'retired', 'enabled' => true]);

        self::assertSame(ConnectionStatus::DISABLED, $this->lifecycle()->disable(self::TENANT, $connection->id, Clients::browser())->status);
        self::assertSame(ConnectionStatus::DELETED, $this->lifecycle()->delete(self::TENANT, $connection->id, Clients::browser())->status);
        self::assertSame(0, Connection::query()->whereKey($connection->id)->count());
    }

    /**
     * Deleting removes the connection and its rows, withdraws its verified
     * claims and revokes its sessions.
     *
     * @return void
     */
    public function testDeletesAConnection(): void
    {
        $rows = $this->populate($this->connection);

        $this->populate($this->other);

        $result = $this->lifecycle()->delete(self::TENANT, $this->connection->id, Clients::browser(), new Caller(new IdentityReference('App\Models\User', '42')));

        self::assertSame(ConnectionStatus::DELETED, $result->status);
        self::assertTrue($result->isChanged());
        self::assertNull($result->connection);
        self::assertSame([[FreshnessOperation::CONNECTION_DELETE, 300]], $this->freshness->asked());

        self::assertSame(self::counts(0, 0, 0, 0, 0, 0), $this->countsOf($this->connection));
        self::assertSame(self::counts(2, 4, 3, 1, 1), $this->countsOf($this->other));
        self::assertSame([[$this->connection->id, $rows['verified'], 1, true]], $this->withdrawal->calls->getArrayCopy());

        $this->assertRevoked(RevocationReason::CONNECTION_DELETED);
        $this->assertEventSequence([ConnectionDeleted::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(ConnectionDeleted::class, $event);
        self::assertSame($this->connection->id, $event->context->connectionId);
        self::assertSame(self::TENANT, $event->context->connectionTenantId);
        self::assertSame('oidc', $event->context->protocol);
        self::assertSame('42', $event->context->actingIdentityId);
    }

    /**
     * A deletion withdraws every verified claim, in id order, and no pending or
     * lapsed one.
     *
     * @return void
     */
    public function testADeletionWithdrawsEachVerifiedClaim(): void
    {
        $first = $this->makeDomain($this->connection, 'one.example.com', ['state' => DomainState::VERIFIED]);

        $this->makeDomain($this->connection, 'pending.example.com');
        $this->makeDomain($this->connection, 'lapsed.example.com', ['state' => DomainState::LAPSED, 'lapsed_at' => $this->clock->now()]);

        $second = $this->makeDomain($this->connection, 'two.example.com', ['state' => DomainState::VERIFIED]);

        $this->makeDomain($this->other, 'other.example.com', ['state' => DomainState::VERIFIED]);

        self::assertTrue($this->lifecycle()->delete(self::TENANT, $this->connection->id, Clients::browser())->isChanged());

        self::assertSame(
            [[$this->connection->id, $first->id, 1, true], [$this->connection->id, $second->id, 1, true]],
            $this->withdrawal->calls->getArrayCopy(),
        );
        self::assertSame(1, Domain::query()->count());
    }

    /**
     * A disabled connection is deleted as an enabled one is.
     *
     * @return void
     */
    public function testDeletesADisabledConnection(): void
    {
        $this->connection->forceFill(['enabled' => false])->save();

        $code = $this->makeHandoffCode($this->connection);

        self::assertSame(ConnectionStatus::DELETED, $this->lifecycle()->delete(self::TENANT, $this->connection->id, Clients::browser())->status);
        self::assertSame(0, HandoffCode::query()->whereKey($code->id)->count());
        $this->assertRevoked(RevocationReason::CONNECTION_DELETED);
    }

    /**
     * Seed the connection with domains, requests, codes, a link and a
     * certificate in each state, by name.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return array<string, string>
     */
    private function populate(Connection $connection): array
    {
        $now     = $this->clock->now();
        $earlier = $now->subMinutes(30);

        $verified = $this->makeDomain($connection, $connection->id . '.example.com', ['state' => DomainState::VERIFIED]);

        $this->makeDomain($connection, 'pending-' . $connection->id . '.example.com');

        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'state'         => null,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'public_key'    => 'the public key of ' . $connection->id,
            'fingerprint'   => hash('sha256', $connection->id),
        ])->save();

        $this->makeLink($connection, 'subject-of-' . $connection->id);

        return [
            'verified'   => $verified->id,
            'pending'    => $this->makeAuthorizationRequest($connection)->id,
            'consumed'   => $this->makeAuthorizationRequest($connection, ['consumed_at' => $now])->id,
            'finished'   => $this->makeAuthorizationRequest($connection, ['consumed_at' => $now, 'completed_at' => $now])->id,
            'voided'     => $this->makeAuthorizationRequest($connection, ['voided_at' => $earlier])->id,
            'unredeemed' => $this->makeHandoffCode($connection)->id,
            'redeemed'   => $this->makeHandoffCode($connection, ['redeemed_at' => $now])->id,
            'voidedCode' => $this->makeHandoffCode($connection, ['voided_at' => $earlier])->id,
        ];
    }

    /**
     * Assert one revocation, inside the transaction, with the connection's
     * scope and the reason.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason  $reason
     * @return void
     */
    private function assertRevoked(RevocationReason $reason): void
    {
        $calls = $this->revocation->calls();

        self::assertCount(1, $calls);
        self::assertSame(1, $calls[0]['level']);

        $scope = $calls[0]['scope'];

        self::assertInstanceOf(RevocationScope::class, $scope);
        self::assertSame(RevocationScopeKind::CONNECTION, $scope->kind);
        self::assertSame($reason, $scope->reason);
        self::assertSame(self::TENANT, $scope->tenantId);
        self::assertSame($this->connection->id, $scope->connectionId);
        self::assertNull($scope->identity);
        self::assertNull($scope->policy);
    }

    /**
     * How many rows the connection holds in each table, its own row included.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return array<string, int>
     */
    private function countsOf(Connection $connection): array
    {
        return [
            'domains'     => Domain::query()->where('connection_id', $connection->id)->count(),
            'requests'    => AuthorizationRequest::query()->where('connection_id', $connection->id)->count(),
            'codes'       => HandoffCode::query()->where('connection_id', $connection->id)->count(),
            'links'       => Link::query()->where('connection_id', $connection->id)->count(),
            'keys'        => ConnectionKey::query()->where('connection_id', $connection->id)->count(),
            'connections' => Connection::query()->whereKey($connection->id)->count(),
        ];
    }

    /**
     * The connection, read again.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function reread(Connection $connection): Connection
    {
        return Connection::query()->whereKey($connection->id)->sole();
    }

    /**
     * Disabling and deleting, by name.
     *
     * @return array<string, \Closure(string, string): \SineMacula\Laravel\Sso\Connections\ConnectionResult>
     */
    private function changes(): array
    {
        return [
            'disable' => fn (string $tenant, string $id): ConnectionResult => $this->lifecycle()->disable($tenant, $id, Clients::browser()),
            'delete'  => fn (string $tenant, string $id): ConnectionResult => $this->lifecycle()->delete($tenant, $id, Clients::browser()),
        ];
    }

    /**
     * The disable and delete helpers, as the container builds them.
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
     * The counts a connection holds, by table.
     *
     * @param  int  $domains
     * @param  int  $requests
     * @param  int  $codes
     * @param  int  $links
     * @param  int  $keys
     * @param  int  $connections
     * @return array<string, int>
     */
    private static function counts(int $domains, int $requests, int $codes, int $links, int $keys, int $connections = 1): array
    {
        return ['domains' => $domains, 'requests' => $requests, 'codes' => $codes, 'links' => $links, 'keys' => $keys, 'connections' => $connections];
    }

    /**
     * When each request was voided, by id, `null` for one never voided.
     *
     * @return array<string, ?string>
     */
    private static function requestsVoided(): array
    {
        $voided = [];

        foreach (AuthorizationRequest::query()->orderBy('id')->get()->all() as $request) {
            $voided[$request->id] = $request->voided_at?->toIso8601String();
        }

        return $voided;
    }

    /**
     * When each handoff code was voided, by id, `null` for one never voided.
     *
     * @return array<string, ?string>
     */
    private static function codesVoided(): array
    {
        $voided = [];

        foreach (HandoffCode::query()->orderBy('id')->get()->all() as $code) {
            $voided[$code->id] = $code->voided_at?->toIso8601String();
        }

        return $voided;
    }
}
