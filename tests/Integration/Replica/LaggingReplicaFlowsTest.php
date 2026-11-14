<?php

declare(strict_types = 1);

namespace Tests\Integration\Replica;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Discovery\DomainRouter;
use SineMacula\Laravel\Sso\Domains\DomainFinder;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\RequestConsumption;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\FlowRoutes;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Fixtures\Clients;
use Tests\TestCase;

/**
 * Integration tests that a read replica contradicting the primary never decides
 * admission.
 *
 * Sticky reads are off. The primary and replica are SQLite files whatever
 * engine the suite runs on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(CompletionService::class)]
#[CoversClass(RequestConsumption::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(LinkStore::class)]
#[CoversClass(KeyRing::class)]
#[CoversClass(DomainFinder::class)]
#[CoversClass(DomainRouter::class)]
#[CoversClass(DatabaseEnforcement::class)]
#[CoversClass(DatabaseSingleUseStore::class)]
#[CoversClass(ServiceProviderDescriptions::class)]
final class LaggingReplicaFlowsTest extends TestCase
{
    use FlowRoutes, InteractsWithLaggingReplica;

    /** @var string The tenant every connection here belongs to. */
    private const string TENANT = 'tenant-replica';

    /** @var string The identity the links here hold. */
    private const string PERSON = 'person-replica';

    /**
     * Create the tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->prepareFlows();
        $this->migrateSsoTablesOnPrimaryAndReplica();
        $this->registerFlowRoutes();
    }

    /**
     * Remove the two files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeLaggingReplicaFiles();

        parent::tearDown();
    }

    /**
     * A connection disabled on the primary refuses a start, though the replica
     * says it is enabled.
     *
     * @return void
     */
    public function testAConnectionDisabledOnThePrimaryRefusesAStart(): void
    {
        $connection = $this->oidc();

        $this->staleOnReplica('connections.table', $connection->id, ['enabled' => false], onPrimary: true);

        $answer = $this->flowStart($connection);

        $answer->assertStatus(422);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE->value, $answer->json('error'));
    }

    /**
     * A connection enabled on the primary works though the replica says
     * disabled.
     *
     * @return void
     */
    public function testAConnectionEnabledOnThePrimaryServes(): void
    {
        $connection = $this->oidc();

        $this->staleOnReplica('connections.table', $connection->id, ['enabled' => false]);

        self::assertSame(self::TENANT, $this->signedIn($connection)['tenant']);
    }

    /**
     * A connection disabled after the start refuses the completion.
     *
     * @return void
     */
    public function testAConnectionDisabledAfterTheStartRefusesTheCompletion(): void
    {
        $connection = $this->oidc();
        $start      = $this->startedFlow($connection);

        $this->staleOnReplica('connections.table', $connection->id, ['enabled' => false], onPrimary: true);

        $this->assertFailedFlow($this->completeFlow($connection, $start), FailureReason::CONNECTION_UNAVAILABLE);
        self::assertSame(0, HandoffCode::query()->useWritePdo()->count());
    }

    /**
     * A trust version raised on the primary overtakes the started request.
     *
     * @return void
     */
    public function testATrustVersionRaisedOnThePrimaryRefusesTheCompletion(): void
    {
        $connection = $this->oidc();
        $start      = $this->startedFlow($connection);

        $this->staleOnReplica('connections.table', $connection->id, ['trust_version' => 1], onPrimary: true);

        $this->assertFailedFlow($this->completeFlow($connection, $start), FailureReason::CONNECTION_UNAVAILABLE);
    }

    /**
     * A trust version raised on the replica alone overtakes nothing.
     *
     * @return void
     */
    public function testATrustVersionRaisedOnTheReplicaAloneChangesNothing(): void
    {
        $connection = $this->oidc();
        $start      = $this->startedFlow($connection);

        $this->staleOnReplica('connections.table', $connection->id, ['trust_version' => 7]);

        $this->completedCode($this->completeFlow($connection, $start));
    }

    /**
     * Every flow works with its rows missing from the replica.
     *
     * @return void
     */
    public function testRowsMissingFromTheReplicaServe(): void
    {
        $connection = $this->oidc();
        $identity   = new IdentityReference('App\Models\User', self::PERSON);
        $linkId     = $this->linkedThroughFlow($connection, $identity);
        $signedIn   = $this->signedIn($connection);

        self::assertSame([$identity->jsonSerialize(), $linkId], [$signedIn['linked'], $signedIn['link_id']]);
        self::assertSame('redeemed', $this->reauthenticatedThroughFlow($connection, $identity, $linkId)['status']);

        foreach (['connections.table', 'authorization_requests.table', 'handoff_codes.table', 'links.table'] as $table) {
            self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(StorageConnection::table($table))->count(), $table);
        }
    }

    /**
     * A connection only the replica still has refuses a start.
     *
     * @return void
     */
    public function testAConnectionOnTheReplicaAloneRefuses(): void
    {
        $connection = $this->oidc();

        $this->onReplicaAlone('connections.table', $connection->id);

        $answer = $this->flowStart($connection);

        $answer->assertStatus(422);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE->value, $answer->json('error'));
    }

    /**
     * A request only the replica has is rejected with no redirect.
     *
     * @return void
     */
    public function testARequestOnTheReplicaAloneIsUnknown(): void
    {
        $connection = $this->oidc();
        $start      = $this->startedFlow($connection);

        $this->onReplicaAlone('authorization_requests.table', $this->requestOf($start)->id);

        $this->completeFlow($connection, $start)->assertStatus(400);
    }

    /**
     * A code only the replica still has is unknown.
     *
     * @return void
     */
    public function testACodeOnTheReplicaAloneIsUnknown(): void
    {
        $connection = $this->oidc();
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start));

        $this->onReplicaAlone('handoff_codes.table', $this->codeOf($start)->id);

        $answer = $this->flowRedeem($connection, 'sign_in', $code, $start['verifier']);

        $answer->assertStatus(422);

        self::assertSame(FailureReason::HANDOFF_UNKNOWN->value, $answer->json('reason'));
    }

    /**
     * A link only the replica has resolves nothing; the person is unlinked.
     *
     * @return void
     */
    public function testALinkOnTheReplicaAloneResolvesNothing(): void
    {
        $connection = $this->oidc();
        $linkId     = $this->linkedThroughFlow($connection, new IdentityReference('App\Models\User', self::PERSON));

        $this->onReplicaAlone('links.table', $linkId);

        self::assertNull($this->signedIn($connection)['linked']);
    }

    /**
     * A replayed code is refused though the replica says unredeemed.
     *
     * @return void
     */
    public function testARedeemedCodeIsAReplayThoughTheReplicaSaysUnredeemed(): void
    {
        $connection = $this->oidc();
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start));
        $stored     = $this->codeOf($start);

        $this->copyRowToReplica(StorageConnection::table('handoff_codes.table'), $stored->id);

        $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk();

        $replay = $this->flowRedeem($connection, 'sign_in', $code, $start['verifier']);

        $replay->assertStatus(422);

        self::assertSame(FailureReason::REPLAYED->value, $replay->json('reason'));
        self::assertNull($this->onTheReplica('handoff_codes.table', $stored->id, 'redeemed_at'));
    }

    /**
     * An unredeemed code redeems, though the replica says it is redeemed.
     *
     * @return void
     */
    public function testAnUnredeemedCodeRedeemsThoughTheReplicaSaysRedeemed(): void
    {
        $connection = $this->oidc();
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start));

        $this->staleOnReplica('handoff_codes.table', $this->codeOf($start)->id, ['redeemed_at' => $this->stamp()]);

        $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk();
    }

    /**
     * A second answer is rejected though the replica says unconsumed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAConsumedRequestIsAReplayThoughTheReplicaSaysUnconsumed(): void
    {
        $connection = $this->oidc();
        $start      = $this->startedFlow($connection);
        $grant      = $this->flowGrant($connection, $start);
        $request    = $this->requestOf($start);

        $this->copyRowToReplica(StorageConnection::table('authorization_requests.table'), $request->id);

        $this->completedCode($this->deliverGrant($connection, $grant));

        $this->deliverGrant($connection, $grant)->assertStatus(400);

        self::assertSame(1, HandoffCode::query()->useWritePdo()->count());
        self::assertNull($this->onTheReplica('authorization_requests.table', $request->id, 'consumed_at'));
    }

    /**
     * An unconsumed request completes though the replica says completed.
     *
     * @return void
     */
    public function testAnUnconsumedRequestCompletesThoughTheReplicaSaysConsumed(): void
    {
        $connection = $this->oidc();
        $start      = $this->startedFlow($connection);

        $changed = ['consumed_at' => $this->stamp(), 'completed_at' => $this->stamp()];

        $this->staleOnReplica('authorization_requests.table', $this->requestOf($start)->id, $changed);

        $this->completedCode($this->completeFlow($connection, $start));
    }

    /**
     * A token signed with the primary's key verifies with nothing fetched.
     *
     * @return void
     */
    public function testAKeyOnThePrimaryVerifiesThoughTheReplicaHoldsAnOldOne(): void
    {
        $connection = $this->oidc();
        $next       = self::flowKey('replica-next', 'replica-next-kid');

        $this->copyRowToReplica(StorageConnection::table('connections.table'), $connection->id);

        Connection::query()->useWritePdo()->findOrFail($connection->id)->forceFill(['jwks' => self::storedKeys($next)])->save();

        $provider = $this->flowProvider($connection);

        $provider->publish($next)->signWith($next);

        $this->completedCode($this->completeFlow($connection, $this->startedFlow($connection)));

        self::assertSame([], $this->jwksFetches($provider));
    }

    /**
     * A token signed with a replica-only key is refused.
     *
     * @return void
     */
    public function testAKeyOnTheReplicaAloneVerifiesNothing(): void
    {
        $connection = $this->oidc();
        $next       = self::flowKey('replica-next', 'replica-next-kid');

        $this->staleOnReplica('connections.table', $connection->id, ['jwks' => self::storedKeys($next)]);

        $start  = $this->startedFlow($connection);
        $tailor = static fn (FakeIdToken $token): FakeIdToken => $token->signedWith($next, 'RS256');

        $this->assertFailedFlow($this->completeFlow($connection, $start, $tailor), FailureReason::SIGNATURE_INVALID);
    }

    /**
     * Only the primary's certificates verify.
     *
     * @return void
     */
    public function testACertificateIsTrustedOnThePrimaryAlone(): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-replica');
        $attacker   = self::flowIdp('idp-replica-attacker');

        $this->onReplicaAlone('keys.table', $this->trustFlowCertificate($connection, $attacker->certificate()));

        $start  = $this->startedFlow($connection);
        $tailor = static fn (FakeSamlResponse $response): FakeSamlResponse => $response->signedBy($attacker->signer());

        $this->assertFailedFlow($this->completeFlow($connection, $start, $tailor), FailureReason::SIGNATURE_INVALID);

        self::assertSame(self::TENANT, $this->signedIn($connection)['tenant']);
    }

    /**
     * A certificate removed on the primary makes the connection unusable.
     *
     * @return void
     */
    public function testACertificateRemovedFromThePrimaryIsNotTrusted(): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-replica');
        $key        = ConnectionKey::query()->useWritePdo()->where('connection_id', $connection->id)->sole();

        $this->startedFlow($connection);

        $this->onReplicaAlone('keys.table', $key->id);

        $answer = $this->flowStart($connection);

        $answer->assertStatus(422);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE->value, $answer->json('error'));
    }

    /**
     * The public keys served are the primary's.
     *
     * @return void
     */
    public function testThePublicKeysServedAreThePrimarys(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-replica-keys', settings: ['client_authentication' => 'private_key_jwt']);
        $key        = app(KeyService::class)->addNext(self::TENANT, $connection->id, KeyUse::CLIENT_ASSERTION, Clients::browser(), KeyType::EC)->key;

        self::assertNotNull($key);
        self::assertCount(1, (array) $this->sendFlowRequest('GET', "/sso/jwks/{$connection->id}")->assertOk()->json('keys'));

        $this->onReplicaAlone('keys.table', $key->id);

        $this->sendFlowRequest('GET', "/sso/jwks/{$connection->id}")->assertNotFound();
    }

    /**
     * Metadata is described from the primary.
     *
     * @return void
     */
    public function testServiceProviderMetadataIsThePrimarys(): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-replica');

        $this->sendFlowRequest('GET', '/sso/metadata/' . self::TENANT . "/{$connection->id}")->assertOk();

        $this->onReplicaAlone('connections.table', $connection->id);

        $this->sendFlowRequest('GET', '/sso/metadata/' . self::TENANT . "/{$connection->id}")->assertNotFound();
    }

    /**
     * A domain missing from the replica routes discovery to its connection.
     *
     * @return void
     */
    public function testADomainMissingFromTheReplicaRoutes(): void
    {
        $connection = $this->oidc();

        $this->flowVerifiedDomain($connection, 'fresh.example.com');

        $this->assertRoutesToProvider($connection, 'person@fresh.example.com');
    }

    /**
     * A domain only the replica still has routes nowhere.
     *
     * @return void
     */
    public function testADomainOnTheReplicaAloneRoutesNowhere(): void
    {
        $connection = $this->oidc();

        $this->onReplicaAlone('domains.table', $this->flowVerifiedDomain($connection, 'gone.example.com'));

        $this->assertRoutesToFallback('person@gone.example.com');
    }

    /**
     * A domain lapsed on the primary routes nowhere.
     *
     * @return void
     */
    public function testADomainLapsedOnThePrimaryRoutesNowhere(): void
    {
        $connection = $this->oidc();

        $this->staleOnReplica('domains.table', $this->flowVerifiedDomain($connection, 'lapsed.example.com'), ['state' => 'lapsed'], onPrimary: true);

        $this->assertRoutesToFallback('person@lapsed.example.com');
    }

    /**
     * A domain verified on the primary routes.
     *
     * @return void
     */
    public function testADomainVerifiedOnThePrimaryRoutes(): void
    {
        $connection = $this->oidc();

        $this->staleOnReplica('domains.table', $this->flowVerifiedDomain($connection, 'verified.example.com'), ['state' => 'lapsed']);

        $this->assertRoutesToProvider($connection, 'person@verified.example.com');
    }

    /**
     * A rule on the primary refuses the sign-in though the replica's is off.
     *
     * @return void
     */
    public function testEnforcementOnThePrimaryRefusesThoughTheReplicaSaysOff(): void
    {
        config()->set('sso.features.enforcement', true);

        $connection = $this->oidc();
        $other      = $this->flowOidcConnection(self::TENANT, 'op-replica-other');
        $rule       = $this->makeEnforcement(['tenant_id' => self::TENANT, 'enabled' => true, 'connection_ids' => [$other->id]]);

        $this->staleOnReplica('enforcement.table', $rule->id, ['enabled' => false]);

        $this->assertFailedFlow($this->completeFlow($connection, $this->startedFlow($connection)), FailureReason::ENFORCEMENT_UNSATISFIED);
    }

    /**
     * With the rule off on the primary the sign-in goes on.
     *
     * @return void
     */
    public function testEnforcementOffOnThePrimaryAdmitsThoughTheReplicaSaysOn(): void
    {
        config()->set('sso.features.enforcement', true);

        $connection = $this->oidc();
        $rule       = $this->makeEnforcement(['tenant_id' => self::TENANT, 'enabled' => false]);

        $this->staleOnReplica('enforcement.table', $rule->id, [
            'enabled'        => true,
            'connection_ids' => (string) json_encode([$this->flowOidcConnection(self::TENANT, 'op-replica-other')->id]),
        ]);

        self::assertSame(self::TENANT, $this->signedIn($connection)['tenant']);
    }

    /**
     * A code is issued under the primary's enforcement version.
     *
     * @return void
     */
    public function testTheEnforcementVersionIsThePrimarys(): void
    {
        config()->set('sso.features.enforcement', true);

        $connection = $this->oidc();
        $version    = str_repeat('a', 26);
        $rule       = $this->makeEnforcement(['tenant_id' => self::TENANT, 'enabled' => true, 'connection_ids' => [$connection->id], 'version' => $version]);

        $this->staleOnReplica('enforcement.table', $rule->id, ['version' => str_repeat('b', 26)]);

        self::assertSame(self::policyVersion($version, [$connection->id]), $this->signedIn($connection)['enforcement_version']);
    }

    /**
     * A link suspended on the primary refuses the sign-in.
     *
     * @return void
     */
    public function testALinkSuspendedOnThePrimaryRefusesTheSignIn(): void
    {
        $connection = $this->oidc();
        $linkId     = $this->linkedThroughFlow($connection, new IdentityReference('App\Models\User', self::PERSON));

        $this->staleOnReplica('links.table', $linkId, ['state' => LinkState::SUSPENDED->value, 'suspended_at' => $this->stamp()], onPrimary: true);

        $this->assertFailedFlow($this->completeFlow($connection, $this->startedFlow($connection)), FailureReason::LINK_SUSPENDED);
    }

    /**
     * A link active on the primary signs in.
     *
     * @return void
     */
    public function testALinkActiveOnThePrimarySignsIn(): void
    {
        $connection = $this->oidc();
        $identity   = new IdentityReference('App\Models\User', self::PERSON);
        $linkId     = $this->linkedThroughFlow($connection, $identity);

        $this->staleOnReplica('links.table', $linkId, ['state' => LinkState::SUSPENDED->value, 'suspended_at' => $this->stamp()]);

        self::assertSame($identity->jsonSerialize(), $this->signedIn($connection)['linked']);
    }

    /**
     * A reservation on the primary holds the subject.
     *
     * @return void
     */
    public function testAReservationOnThePrimaryHoldsTheSubject(): void
    {
        $connection = $this->oidc();

        $this->reservation($connection);

        $this->assertFailedFlow($this->completeFlow($connection, $this->startedFlow($connection)), FailureReason::LINK_RESERVED);
    }

    /**
     * A reservation only the replica has holds nothing.
     *
     * @return void
     */
    public function testAReservationOnTheReplicaAloneHoldsNothing(): void
    {
        $connection = $this->oidc();

        $this->onReplicaAlone('links.table', $this->reservation($connection));

        self::assertSame(self::TENANT, $this->signedIn($connection)['tenant']);
    }

    /**
     * An assertion recorded on the primary is a replay.
     *
     * @return void
     */
    public function testAnAssertionRecordedOnThePrimaryIsAReplay(): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-replica');
        $tailor     = static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['assertion_id' => '_assertion-replica-replayed']);

        $this->completedCode($this->completeFlow($connection, $this->startedFlow($connection), $tailor));

        $this->assertFailedFlow($this->completeFlow($connection, $this->startedFlow($connection), $tailor), FailureReason::REPLAYED);
    }

    /**
     * An assertion recorded only on the replica is no replay.
     *
     * @return void
     */
    public function testAnAssertionRecordedOnTheReplicaAloneCompletes(): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-replica');
        $tailor     = static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['assertion_id' => '_assertion-replica-recorded']);

        $this->completedCode($this->completeFlow($connection, $this->startedFlow($connection), $tailor));

        $record = SingleUseKey::query()->useWritePdo()->whereNotIn('namespace', [RequestConsumption::NAMESPACE, HandoffRedemption::NAMESPACE])->sole();

        $this->onReplicaAlone('single_use.table', $record->id);

        $this->completedCode($this->completeFlow($connection, $this->startedFlow($connection), $tailor));
    }

    /**
     * The store's own answer is the primary's, in both directions.
     *
     * @return void
     */
    public function testTheSingleUseStoreAnswersFromThePrimary(): void
    {
        $store = app(SingleUseStore::class);
        $until = $this->flowClock->now()->addHour();

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('replica_test', 'the-key', $until));
        self::assertSame(SingleUseOutcome::SEEN, $store->record('replica_test', 'the-key', $until));

        $record = SingleUseKey::query()->useWritePdo()->where('namespace', 'replica_test')->sole();

        $this->onReplicaAlone('single_use.table', $record->id);

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('replica_test', 'the-key', $until));
    }

    /**
     * Every flow runs with the replica's tables gone.
     *
     * @return void
     */
    public function testAFlowNeverNeedsTheReplica(): void
    {
        $schema = DB::connection(self::REPLICA_CONNECTION)->getSchemaBuilder();

        foreach (array_keys(StorageConnection::TABLES) as $key) {
            $schema->dropIfExists(StorageConnection::table($key));
        }

        $oidc     = $this->oidc();
        $saml     = $this->flowSamlConnection(self::TENANT, 'idp-replica', ['idp_initiated' => true, 'idp_initiated_start_url' => self::FLOW_START_URL]);
        $identity = new IdentityReference('App\Models\User', self::PERSON);
        $linkId   = $this->linkedThroughFlow($oidc, $identity);

        $this->flowVerifiedDomain($oidc, 'needless.example.com');

        self::assertSame($identity->jsonSerialize(), $this->signedIn($oidc)['linked']);
        self::assertSame('redeemed', $this->reauthenticatedThroughFlow($oidc, $identity, $linkId)['status']);
        self::assertSame(self::TENANT, $this->signedIn($saml)['tenant']);

        $this->assertRoutesToProvider($oidc, 'person@needless.example.com');
        $this->assertRoutesToFallback('person@nowhere.example.com');

        $this->postSamlResponse($saml, $this->flowSamlResponse($saml))->assertStatus(303);
        $this->sendFlowRequest('GET', '/sso/metadata/' . self::TENANT . "/{$saml->id}")->assertOk();
    }

    /**
     * Use the lagging replica.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->configureLaggingReplica(app(ConfigRepository::class));
    }

    /**
     * Copy the row to the replica, then change the copy, or with `onPrimary`
     * the original.
     *
     * @param  string  $table
     * @param  string  $id
     * @param  array<string, mixed>  $change
     * @param  bool  $onPrimary
     * @return void
     */
    private function staleOnReplica(string $table, string $id, array $change, bool $onPrimary = false): void
    {
        $name = StorageConnection::table($table);

        $this->copyRowToReplica($name, $id);

        DB::connection($onPrimary ? self::PRIMARY_CONNECTION : self::REPLICA_CONNECTION)->table($name)->where('id', $id)->update($change);
    }

    /**
     * What the replica holds in the column of the row.
     *
     * @param  string  $table
     * @param  string  $id
     * @param  string  $column
     * @return mixed
     */
    private function onTheReplica(string $table, string $id, string $column): mixed
    {
        return DB::connection(self::REPLICA_CONNECTION)->table(StorageConnection::table($table))->where('id', $id)->value($column);
    }

    /**
     * Move the row from the primary to the replica.
     *
     * @param  string  $table
     * @param  int|string  $id
     * @return void
     */
    private function onReplicaAlone(string $table, int|string $id): void
    {
        $name = StorageConnection::table($table);

        $this->copyRowToReplica($name, $id);

        DB::connection(self::PRIMARY_CONNECTION)->table($name)->where('id', $id)->delete();
    }

    /**
     * An enabled OIDC connection of a provider of its own.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function oidc(): Connection
    {
        return $this->flowOidcConnection(self::TENANT, 'op-replica', self::flowKey('replica'));
    }

    /**
     * A live reservation of the subject the provider asserts, answering its id.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return string
     */
    private function reservation(Connection $connection): string
    {
        return $this->makeLink($connection, FakeOpenIdProvider::SUBJECT, [
            'issuer'                 => $this->flowProvider($connection)->issuer,
            'state'                  => LinkState::RESERVED,
            'provenance'             => LinkOrigin::VERIFIED_DOMAIN,
            'reservation_id'         => str_repeat('r', 26),
            'reservation_expires_at' => $this->flowClock->now()->addHour(),
        ])->id;
    }

    /**
     * The request of the start, read from the primary.
     *
     * @param  array{reference: string}  $start
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function requestOf(array $start): AuthorizationRequest
    {
        return AuthorizationRequest::query()->useWritePdo()->where('reference', $start['reference'])->sole();
    }

    /**
     * The code of the start, read from the primary.
     *
     * @param  array{reference: string}  $start
     * @return \SineMacula\Laravel\Sso\Models\HandoffCode
     */
    private function codeOf(array $start): HandoffCode
    {
        return HandoffCode::query()->useWritePdo()->where('request_reference', $start['reference'])->sole();
    }

    /**
     * Now, as a time column stores it.
     *
     * @return string
     */
    private function stamp(): string
    {
        return UtcDateTime::format(new HandoffCode, $this->flowClock->now());
    }

    /**
     * The stored form of a key set of one key.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @return string
     */
    private static function storedKeys(FakeSigningKey $key): string
    {
        return (string) ProviderKeySet::read((string) json_encode(['keys' => [$key->jwk()]]), AlgorithmAllowList::of(['RS256']), 65536, 50)?->toStored();
    }

    /**
     * The JWKS requests the provider was sent.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @return list<string>
     */
    private function jwksFetches(FakeOpenIdProvider $provider): array
    {
        $urls = [];

        foreach ($this->flowFetcher->requests() as $request) {

            if ($request->url !== $provider->endpoint('jwks')) {
                continue;
            }

            $urls[] = $request->url;
        }

        return $urls;
    }

    /**
     * Assert discovery sends the email to the connection's provider.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $email
     * @return void
     */
    private function assertRoutesToProvider(Connection $connection, string $email): void
    {
        $answer        = $this->sendFlowRequest('POST', '/sso/discover', ['email' => $email])->assertOk();
        $authorization = $this->flowProvider($connection)->endpoint('authorization');

        self::assertNotSame('', $authorization);
        self::assertStringStartsWith($authorization, self::flowText($answer->json('navigation.url')));
    }

    /**
     * Assert discovery sends the email to the application's fallback.
     *
     * @param  string  $email
     * @return void
     */
    private function assertRoutesToFallback(string $email): void
    {
        self::assertSame(self::FLOW_FALLBACK_URL, $this->sendFlowRequest('POST', '/sso/discover', ['email' => $email])->assertOk()->json('navigation.url'));
    }
}
