<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Completion\CompletionLocks;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionStep;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Completion\Stages\CheckEnforcement;
use SineMacula\Laravel\Sso\Completion\Stages\CheckPurpose;
use SineMacula\Laravel\Sso\Completion\Stages\ConsumeRequest;
use SineMacula\Laravel\Sso\Completion\Stages\CorrelateResponse;
use SineMacula\Laravel\Sso\Completion\Stages\DecideUnlinked;
use SineMacula\Laravel\Sso\Completion\Stages\DomainReservation;
use SineMacula\Laravel\Sso\Completion\Stages\IssueHandoff;
use SineMacula\Laravel\Sso\Completion\Stages\Provisioning;
use SineMacula\Laravel\Sso\Completion\Stages\RecordReplay;
use SineMacula\Laravel\Sso\Completion\Stages\ResolveLink;
use SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse;
use SineMacula\Laravel\Sso\Completion\UnsolicitedReinitiation;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\RedirectUriResolver;
use SineMacula\Laravel\Sso\Contracts\ReinitiatingDriver;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\UnsolicitedResponseReinitiated;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Metadata\MetadataSettings;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Reinitiation;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\RecordsLockOrder;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEnforcement;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Enforcement\ListedExemption;
use Tests\Fixtures\Enforcement\ScriptedInheritance;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\ExampleSettings;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Feature tests for the completion pipeline and unsolicited re-initiation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(CompletionLocks::class)]
#[CoversClass(UnsolicitedReinitiation::class)]
final class CompletionPipelineTest extends TestCase
{
    use RecordsEventSequences, RecordsLockOrder, UsesConnections, UsesEnforcement, UsesFlowTables;

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-piped-request-0001';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Pq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var string The name the re-initiating driver is registered under. */
    private const string REINITIATING = 'reinitiating';

    /** @var string The start URL a re-initiation sends the browser to. */
    private const string START_URL = 'https://app.example.com/sso/start?connection=reinitiating';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Protocols\VerifyingDriver The driver the connection runs over. */
    private VerifyingDriver $driver;

    /** @var \Tests\Fixtures\Handoffs\RecordingHandoffIssuer The handoff issuer. */
    private RecordingHandoffIssuer $issuer;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /** @var \ArrayObject<int, array{0: string, 1: int}> Each step a spy ran, with the transaction level it ran at. */
    private \ArrayObject $ran;

    /** @var \ArrayObject<string, array{0: \SineMacula\Laravel\Sso\Completion\StageOutcome, 1: bool}> Each spy's answer, and whether its request was completed. */
    private \ArrayObject $answered;

    /** @var \ArrayObject<string, mixed> What the re-initiating driver answers (`answer`), and what it runs first (`change`), if anything. */
    private \ArrayObject $script;

    /**
     * Bind a fixed clock, the issuer and a linker, and create a connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock    = new FixedClock('2026-11-01T09:30:00Z');
        $this->driver   = new VerifyingDriver;
        $this->issuer   = new RecordingHandoffIssuer;
        $this->ran      = new \ArrayObject;
        $this->answered = new \ArrayObject;
        $this->script   = new \ArrayObject;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(HandoffIssuer::class, $this->issuer);
        $this->app?->instance(Linker::class, self::linker());
        $this->app?->instance('request', Request::create('/auth/sso/connections/x/callback', 'GET', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'protocol' => VerifyingDriver::NAME,
            'enabled'  => true,
            'settings' => ['issuer' => VerifyingDriver::ISSUER],
        ]);

        $this->startRecordingEvents();
    }

    /**
     * Each step has its own stage.
     *
     * @return void
     */
    public function testEachStepHasItsStage(): void
    {
        $stages = [];

        foreach (CompletionStep::cases() as $step) {
            $stages[$step->value] = CompletionPipeline::stageClass($step);
        }

        self::assertSame([
            'correlation'        => CorrelateResponse::class,
            'consumption'        => ConsumeRequest::class,
            'validation'         => ValidateResponse::class,
            'replay_recording'   => RecordReplay::class,
            'link_resolution'    => ResolveLink::class,
            'enforcement'        => CheckEnforcement::class,
            'purpose_rules'      => CheckPurpose::class,
            'domain_reservation' => DomainReservation::class,
            'provisioning'       => Provisioning::class,
            'unlinked_decision'  => DecideUnlinked::class,
            'handoff_issuance'   => IssueHandoff::class,
        ], $stages);
    }

    /**
     * The stages run in step order, the locked ones in one transaction.
     *
     * @return void
     */
    public function testTheStagesRunInTheStepsOrderAndTheLockedOnesInOneTransaction(): void
    {
        $request = $this->request();

        $this->spyOnEveryStep();

        self::assertTrue($this->completeAtCallback()->isCompleted());

        self::assertSame(array_map(static fn (CompletionStep $step): array => [$step->value, $step->isLocked() ? 1 : 0], CompletionStep::cases()), $this->ran->getArrayCopy());
        self::assertSame(
            [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
            array_map(static fn (array $ran): int => $ran[1], $this->ran->getArrayCopy()),
        );
        self::assertFalse($this->spied('handoff_issuance')[1]);
        self::assertNotNull($this->reread($request)->completed_at);
    }

    /**
     * The locked stages are given the rows as they were locked.
     *
     * @return void
     */
    public function testTheLockedStagesAreGivenTheRowsAsLocked(): void
    {
        $this->request();

        $this->spyOnEveryStep();

        self::assertTrue($this->completeAtCallback()->isCompleted());

        $before = $this->spied('validation')[0]->state;
        $after  = $this->spied('link_resolution')[0]->state;

        self::assertNotSame($before->connection, $after->connection);
        self::assertNotSame($before->authorizationRequest, $after->authorizationRequest);
        self::assertSame($before->connection?->id, $after->connection?->id);
        self::assertSame($before->authorizationRequest?->id, $after->authorizationRequest?->id);
        self::assertSame($before->consumed, $after->consumed);
        self::assertSame($before->application, $after->application);
        self::assertNotNull($after->result);
        self::assertSame($before->result, $after->result);
    }

    /**
     * A refusal ends the pipeline.
     *
     * @return void
     */
    public function testARefusalEndsThePipeline(): void
    {
        $this->request();
        $this->spyOnEveryStep();

        $this->driver->refusal = FailureReason::SIGNATURE_INVALID;

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->completeAtCallback()->reason);
        self::assertSame(['correlation', 'consumption', 'validation'], $this->stepsRan());

        $this->ran->exchangeArray([]);
        $this->driver->refusal = null;

        $this->request(['reference' => str_repeat('Q', 32), 'state_digest' => hash('sha256', 'a-second-state')]);
        $this->app?->instance(CheckEnforcement::class, $this->refusing(FailureReason::ENFORCEMENT_UNSATISFIED));

        $result = $this->completeAtCallback('a-second-state');

        self::assertSame(FailureReason::ENFORCEMENT_UNSATISFIED, $result->reason);
        self::assertSame(['correlation', 'consumption', 'validation', 'replay_recording', 'link_resolution', 'enforcement'], $this->stepsRan());
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * The request's `completed_at` is set whether it completed or was refused.
     *
     * @return void
     */
    public function testCompletedAtIsSetWhetherTheCompletionCompletedOrWasRefused(): void
    {
        $completed = $this->request();

        $this->clock->advance(1);

        self::assertTrue($this->completeAtCallback()->isCompleted());

        $refused = $this->request(['reference' => str_repeat('R', 32), 'state_digest' => hash('sha256', 'refused')]);

        $this->driver->refusal = FailureReason::ASSERTION_EXPIRED;
        $this->clock->advance(1);

        self::assertTrue($this->completeAtCallback('refused')->isFailed());

        $expired = $this->request(['reference' => str_repeat('E', 32), 'state_digest' => hash('sha256', 'expired'), 'expires_at' => $this->clock->now()]);

        $this->clock->advance(1);

        self::assertSame(FailureReason::REQUEST_EXPIRED, $this->completeAtCallback('expired')->reason);
        self::assertTrue($this->completeAtCallback('unknown')->isRejected());

        self::assertSame(
            ['2026-11-01T09:30:01+00:00', '2026-11-01T09:30:02+00:00', '2026-11-01T09:30:03+00:00'],
            array_map(fn (AuthorizationRequest $request): ?string => $this->reread($request)->completed_at?->toIso8601String(), [$completed, $refused, $expired]),
        );
    }

    /**
     * A request voided during validation is refused under the lock.
     *
     * @return void
     */
    public function testARequestVoidedAfterConsumptionIsRefusedUnderTheLock(): void
    {
        $request = $this->request();

        $this->spyOnEveryStep();

        $this->driver->onComplete = function () use ($request): void {
            DB::connection(StorageConnection::name())->table(StorageConnection::table('authorization_requests.table'))
                ->where('id', $request->id)
                ->update(['voided_at' => '2026-11-01 09:30:00']);
        };

        $result = $this->completeAtCallback();

        self::assertSame(['failed', 'connection_unavailable', 'https://app.example.com/sso', self::REFERENCE], self::summary($result));
        self::assertSame(['correlation', 'consumption', 'validation'], $this->stepsRan());
        self::assertSame([], $this->issuer->grants());
        self::assertNotNull($this->reread($request)->completed_at);
    }

    /**
     * A request of an older trust version is refused before validation.
     *
     * @return void
     */
    public function testARequestOfAnOlderTrustVersionIsRefusedBeforeValidation(): void
    {
        $request = $this->request();

        Connection::query()->whereKey($this->connection->id)->increment('trust_version');

        $this->spyOnEveryStep();

        $validated = false;

        $this->driver->onComplete = static function () use (&$validated): void {
            $validated = true;
        };

        $result = $this->completeAtCallback();

        self::assertSame(['failed', 'connection_unavailable', 'https://app.example.com/sso', self::REFERENCE], self::summary($result));
        self::assertSame(['correlation', 'consumption'], $this->stepsRan());
        self::assertFalse($validated);
        self::assertSame([], $this->issuer->grants());
        self::assertNotNull($this->reread($request)->completed_at);
    }

    /**
     * A trust version raised during validation is refused under the lock.
     *
     * @return void
     */
    public function testATrustVersionRaisedAfterConsumptionIsRefusedUnderTheLock(): void
    {
        $request    = $this->request();
        $connection = $this->connection;

        $this->spyOnEveryStep();

        $this->driver->onComplete = static function () use ($connection): void {
            Connection::query()->whereKey($connection->id)->increment('trust_version');
        };

        $result = $this->completeAtCallback();

        self::assertSame(['failed', 'connection_unavailable', 'https://app.example.com/sso', self::REFERENCE], self::summary($result));
        self::assertSame(['correlation', 'consumption', 'validation'], $this->stepsRan());
        self::assertSame([], $this->issuer->grants());
        self::assertNull($this->reread($request)->voided_at);
        self::assertNotNull($this->reread($request)->completed_at);
    }

    /**
     * A connection disabled during validation is refused under the lock.
     *
     * @return void
     */
    public function testAConnectionDisabledAfterValidationBeganIsRefusedUnderTheLock(): void
    {
        $this->request();

        $connection = $this->connection;

        $this->driver->onComplete = static function () use ($connection): void {
            Connection::query()->whereKey($connection->id)->sole()->forceFill(['enabled' => false])->save();
        };

        self::assertSame(['failed', 'connection_unavailable', 'https://app.example.com/sso', self::REFERENCE], self::summary($this->completeAtCallback()));
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * A connection or request row gone during validation is refused.
     *
     * @return void
     */
    public function testARowGoneAfterValidationBeganIsRefusedUnderTheLock(): void
    {
        $request    = $this->request();
        $connection = $this->connection;

        $this->driver->onComplete = static function () use ($connection): void {
            DB::connection(StorageConnection::name())->table(StorageConnection::table('connections.table'))->where('id', $connection->id)->delete();
        };

        self::assertSame(['failed', 'connection_unavailable', 'https://app.example.com/sso', self::REFERENCE], self::summary($this->completeAtCallback()));
        self::assertNotNull($this->reread($request)->completed_at);

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);

        $gone = $this->request(['reference' => str_repeat('G', 32), 'state_digest' => hash('sha256', 'gone')]);

        $this->driver->onComplete = static function () use ($gone): void {
            DB::connection(StorageConnection::name())->table(StorageConnection::table('authorization_requests.table'))->where('id', $gone->id)->delete();
        };

        self::assertSame(['failed', 'connection_unavailable', 'https://app.example.com/sso', str_repeat('G', 32)], self::summary($this->completeAtCallback('gone')));
        self::assertSame(0, AuthorizationRequest::query()->whereKey($gone->id)->count());
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * The locked steps lock enforcement, connections by id, then the request.
     *
     * @return void
     */
    public function testTheLockedStepsTakeTheEnforcementThenTheConnectionsThenTheRequest(): void
    {
        config()->set('sso.features.enforcement', true);

        $other = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true]);
        $rule  = $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$other->id, $this->connection->id]]);
        $ids   = [$this->connection->id, $other->id];

        sort($ids, SORT_STRING);

        $this->request();
        $this->spyOnEveryStep();
        $this->recordLockOrder();

        self::assertTrue($this->completeAtCallback()->isCompleted());
        self::assertSame(
            ['connections ' . $this->connection->id, 'request', 'enforcement upsert', 'enforcement', 'connections ' . implode(', ', $ids), 'request'],
            $this->lockOrder(),
        );
        self::assertSame(2, $this->enforcementStatements());
        self::assertSame(
            ['tenant_id' => 'tenant-1', 'enforcing_tenant_id' => 'tenant-1', 'required' => true, 'connection_ids' => $ids, 'version' => $rule->version],
            $this->spied('enforcement')[0]->state->enforcementPolicy?->jsonSerialize(),
        );
        self::assertCount(1, $this->issuer->grants());
    }

    /**
     * The locked policy refuses a connection that does not satisfy it.
     *
     * @return void
     */
    public function testTheLockedPolicyRefusesAConnectionThatDoesNotSatisfyIt(): void
    {
        config()->set('sso.features.enforcement', true);

        $other = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true]);

        $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$other->id]]);
        $this->request();

        self::assertSame(['failed', 'enforcement_unsatisfied', 'https://app.example.com/sso', self::REFERENCE], self::summary($this->completeAtCallback()));
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * The completion never asks the exemption contract.
     *
     * @return void
     */
    public function testTheCompletionNeverAsksTheExemptionContract(): void
    {
        config()->set('sso.features.enforcement', true);

        $exemption = new ListedExemption([new IdentityReference('App\Models\User', '42')]);
        $other     = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true]);

        $this->app?->instance(EnforcementExemption::class, $exemption);
        $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$other->id]]);
        $this->request();

        self::assertSame(['failed', 'enforcement_unsatisfied', 'https://app.example.com/sso', self::REFERENCE], self::summary($this->completeAtCallback()));
        self::assertSame([], $this->issuer->grants());
        self::assertSame([], $exemption->asked());
    }

    /**
     * A tenant with no rule is locked through an unconfigured row.
     *
     * @return void
     */
    public function testATenantWithNoRuleIsLockedThroughAnUnconfiguredRow(): void
    {
        config()->set('sso.features.enforcement', true);

        $this->request();

        self::assertTrue($this->completeAtCallback()->isCompleted());
        self::assertNull(TenantEnforcement::query()->sole()->version);
        self::assertCount(1, $this->issuer->grants());
    }

    /**
     * No enforcement is locked with the feature off or once refused.
     *
     * @return void
     */
    public function testNoEnforcementIsLockedWithTheFeatureOffOrForARefusedCompletion(): void
    {
        $inheritance = new ScriptedInheritance(['tenant-1']);

        $this->app?->instance(EnforcementInheritance::class, $inheritance);
        $this->request();
        $this->recordLockOrder();

        self::assertTrue($this->completeAtCallback()->isCompleted());
        self::assertSame(['connections ' . $this->connection->id, 'request', 'connections ' . $this->connection->id, 'request'], $this->lockOrder());

        config()->set('sso.features.enforcement', true);

        $this->request(['reference' => str_repeat('R', 32), 'state_digest' => hash('sha256', 'refused')]);
        $this->driver->refusal = FailureReason::SIGNATURE_INVALID;

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->completeAtCallback('refused')->reason);
        self::assertSame(0, $this->enforcementStatements());
        self::assertSame(0, TenantEnforcement::query()->count());
        self::assertSame([], $inheritance->asked());
    }

    /**
     * An enforcing tenant that moved since the lock is refused.
     *
     * @return void
     */
    public function testAnEnforcingTenantThatMovedSinceTheLockIsRefused(): void
    {
        config()->set('sso.features.enforcement', true);

        $inheritance = new ScriptedInheritance(['tenant-1', 'parent-1']);
        $request     = $this->request();

        $this->app?->instance(EnforcementInheritance::class, $inheritance);
        $this->spyOnEveryStep();

        self::assertSame(['failed', 'connection_unavailable', 'https://app.example.com/sso', self::REFERENCE], self::summary($this->completeAtCallback()));
        self::assertSame(['correlation', 'consumption', 'validation'], $this->stepsRan());
        self::assertSame([['tenant-1', 'web'], ['tenant-1', 'web']], $inheritance->asked());
        self::assertSame([], $this->issuer->grants());
        self::assertNotNull($this->reread($request)->completed_at);
    }

    /**
     * A step whose stage is not a stage propagates and rolls back.
     *
     * @return void
     */
    public function testAStepWhoseStageIsNotAStageIsAMisconfiguration(): void
    {
        $request = $this->request();

        $this->app?->instance(ResolveLink::class, new \stdClass);

        try {
            $this->completeAtCallback();
            self::fail('A step whose stage is not a stage completed.');
        } catch (\LogicException $e) {
            self::assertSame('The [link_resolution] step resolved to stdClass, which is not a completion stage.', $e->getMessage());
        }

        self::assertNull($this->reread($request)->completed_at);
        self::assertNotNull($this->reread($request)->consumed_at);
        $this->assertNoEvents();
    }

    /**
     * A misconfigured redirect URI resolver propagates and rolls back.
     *
     * @return void
     */
    public function testAMisconfiguredRedirectUriResolverPropagatesAndRollsBack(): void
    {
        $request = $this->request();

        $this->app?->instance(RedirectUriResolver::class, new readonly class implements RedirectUriResolver {
            /**
             * A URI no redirect URI may be.
             *
             * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return string
             */
            #[\Override]
            public function redirectUri(Application $application, SsoConnection $connection): string
            {
                unset($application, $connection);

                return 'http://app.example.com/sso#fragment';
            }
        });

        try {
            $this->completeAtCallback();
            self::fail('A misconfigured resolver completed.');
        } catch (\LogicException $e) {
            self::assertSame('The bound redirect URI resolver answered the [web] application with a URI that is not an exact redirect URI.', $e->getMessage());
        }

        self::assertCount(1, $this->issuer->grants());
        self::assertNull($this->reread($request)->completed_at);
        $this->assertNoEvents();
    }

    /**
     * An unsolicited response is re-initiated without consuming a request.
     *
     * @return void
     */
    public function testAnUnsolicitedResponseIsReinitiatedWithoutConsumingARequest(): void
    {
        $connection = $this->reinitiatingConnection();
        $request    = $this->makeAuthorizationRequest($connection, ['state_digest' => hash('sha256', self::STATE)]);

        $this->script['answer'] = Reinitiation::allowed(self::START_URL, $this->record(300));
        $this->spyOnEveryStep();

        $result = $this->completeAtAssertionConsumerService($connection);

        self::assertSame(['reinitiated', null, null, null, self::START_URL], [...self::summary($result), $result->startUrl]);
        self::assertSame([['correlation', 0], ['replay_recording', 1]], $this->ran->getArrayCopy());
        self::assertSame(1, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
        self::assertSame([null, null], [$this->reread($request)->consumed_at, $this->reread($request)->completed_at]);
        self::assertSame([], $this->issuer->grants());
        $this->assertEventSequence([UnsolicitedResponseReinitiated::class]);
        self::assertSame([$connection->id, 'tenant-1', self::REINITIATING], self::contextOf($this->recordedEvents()[0]->context()));
    }

    /**
     * A refused re-initiation reports one failure and records nothing.
     *
     * @return void
     */
    public function testARefusedReinitiationIsRejected(): void
    {
        $connection = $this->reinitiatingConnection();

        $this->script['answer'] = Reinitiation::refused(FailureReason::SIGNATURE_INVALID);
        $this->spyOnEveryStep();

        self::assertSame(['rejected', 'signature_invalid', null, null], self::summary($this->completeAtAssertionConsumerService($connection)));
        self::assertSame(['correlation'], $this->stepsRan());
        self::assertSame(0, SingleUseKey::query()->count());
        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::ASSERTION, FailureReason::SIGNATURE_INVALID);

        self::assertSame([$connection->id, 'tenant-1', self::REINITIATING], self::contextOf($failure->context()));
    }

    /**
     * Rows of `[change]` made to the connection between validation and lock.
     *
     * @return iterable<string, array{0: \Closure(string): void}>
     */
    public static function provideConnectionChanges(): iterable
    {
        yield 'disabled' => [static function (string $id): void {
            Connection::query()->whereKey($id)->sole()->forceFill(['enabled' => false])->save();
        }];
        yield 'made incomplete' => [static function (string $id): void {
            Connection::query()->whereKey($id)->sole()->forceFill(['settings' => []])->save();
        }];
        yield 'its trust version raised' => [static function (string $id): void {
            Connection::query()->whereKey($id)->sole()->increment('trust_version');
        }];
        yield 'deleted' => [static function (string $id): void {
            DB::connection(StorageConnection::name())->table(StorageConnection::table('connections.table'))->where('id', $id)->delete();
        }];
    }

    /**
     * A connection changed since validation is refused under the lock.
     *
     * @param  \Closure(string): void  $change
     * @return void
     */
    #[DataProvider('provideConnectionChanges')]
    public function testAConnectionChangedSinceValidationIsRefusedUnderTheLock(\Closure $change): void
    {
        $connection = $this->reinitiatingConnection();

        $this->script['answer'] = Reinitiation::allowed(self::START_URL, $this->record(300));
        $this->script['change'] = static fn () => $change($connection->id);
        $this->spyOnEveryStep();

        self::assertSame(['rejected', 'connection_unavailable', null, null], self::summary($this->completeAtAssertionConsumerService($connection)));
        self::assertSame(['correlation'], $this->stepsRan());
        self::assertSame(0, SingleUseKey::query()->count());
        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::ASSERTION, FailureReason::CONNECTION_UNAVAILABLE);
    }

    /**
     * Rows of `[start URL, reason]` the driver answers under the lock.
     *
     * @return iterable<string, array{0: ?string, 1: string}>
     */
    public static function provideStartUrlChanges(): iterable
    {
        yield 'IdP-initiated sign-in turned off' => [null, 'unsolicited_not_allowed'];
        yield 'another start URL' => [self::START_URL . '/other', 'connection_unavailable'];
    }

    /**
     * A start URL changed since validation is refused under the lock.
     *
     * @param  ?string  $startUrl
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('provideStartUrlChanges')]
    public function testAStartUrlChangedSinceValidationIsRefusedUnderTheLock(?string $startUrl, string $reason): void
    {
        $connection = $this->reinitiatingConnection();
        $script     = $this->script;

        $this->script['answer'] = Reinitiation::allowed(self::START_URL, $this->record(300));
        $this->script['change'] = static function () use ($script, $startUrl): void {
            $script['start_url'] = $startUrl;
        };
        $this->spyOnEveryStep();

        $result = $this->completeAtAssertionConsumerService($connection);

        self::assertSame(['rejected', $reason, null, null, null], [...self::summary($result), $result->startUrl]);
        self::assertSame(['correlation'], $this->stepsRan());
        self::assertSame(0, SingleUseKey::query()->count());
        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::ASSERTION, FailureReason::from($reason));
    }

    /**
     * Rows of `[limit, seconds, reason]` for metadata lapsing in a minute.
     *
     * @return iterable<string, array{0: string, 1: int, 2: ?string}>
     */
    public static function provideMetadataLapses(): iterable
    {
        foreach (['valid_until', 'stale_limit'] as $limit) {
            yield "{$limit}, a second before" => [$limit, 59, null];
            yield "{$limit}, at the instant" => [$limit, 60, 'metadata_expired'];
            yield "{$limit}, a second after" => [$limit, 61, 'metadata_expired'];
        }
    }

    /**
     * Metadata that lapsed during validation is refused under the lock.
     *
     * @param  string  $limit
     * @param  int  $seconds
     * @param  ?string  $reason
     * @return void
     */
    #[DataProvider('provideMetadataLapses')]
    public function testMetadataThatLapsedWhileTheResponseWasValidatedIsRefusedUnderTheLock(string $limit, int $seconds, ?string $reason): void
    {
        $request = $this->request();
        $clock   = $this->clock;

        $this->lapseInAMinute($this->connection, $limit);
        $this->spyOnEveryStep();

        $this->driver->onComplete = static function () use ($clock, $seconds): void {
            $clock->advance($seconds);
        };

        $result = $this->completeAtCallback();

        self::assertSame([$reason === null ? 'completed' : 'failed', $reason], [$result->status->value, $result->reason?->value]);
        self::assertCount($reason === null ? 11 : 3, $this->stepsRan());
        self::assertCount($reason === null ? 1 : 0, $this->issuer->grants());
        self::assertNotNull($this->reread($request)->completed_at);
    }

    /**
     * Metadata that lapsed during unsolicited validation is refused.
     *
     * @param  string  $limit
     * @param  int  $seconds
     * @param  ?string  $reason
     * @return void
     */
    #[DataProvider('provideMetadataLapses')]
    public function testMetadataThatLapsedWhileAnUnsolicitedResponseWasValidatedIsRefusedUnderTheLock(string $limit, int $seconds, ?string $reason): void
    {
        $connection = $this->reinitiatingConnection();
        $clock      = $this->clock;

        $this->lapseInAMinute($connection, $limit);

        $this->script['answer'] = Reinitiation::allowed(self::START_URL, $this->record(300));
        $this->script['change'] = static function () use ($clock, $seconds): void {
            $clock->advance($seconds);
        };

        $result = $this->completeAtAssertionConsumerService($connection);

        self::assertSame(
            [$reason === null ? 'reinitiated' : 'rejected', $reason, $reason === null ? self::START_URL : null],
            [$result->status->value, $result->reason?->value, $result->startUrl],
        );
        self::assertSame($reason === null ? 1 : 0, SingleUseKey::query()->count());
    }

    /**
     * The re-initiation's record is made as the replay step makes any.
     *
     * @return void
     */
    public function testTheRecordIsMadeAsTheReplayStepMakesAny(): void
    {
        $connection = $this->reinitiatingConnection();

        $this->script['answer'] = Reinitiation::allowed(self::START_URL, $this->record(0));

        self::assertSame(['rejected', 'assertion_expired', null, null], self::summary($this->completeAtAssertionConsumerService($connection)));
        self::assertSame(0, SingleUseKey::query()->count());

        $this->script['answer'] = Reinitiation::allowed(self::START_URL, $this->record(1));

        self::assertTrue($this->completeAtAssertionConsumerService($connection)->isReinitiated());
        self::assertSame(['rejected', 'replayed', null, null], self::summary($this->completeAtAssertionConsumerService($connection)));
        self::assertSame(1, SingleUseKey::query()->count());
        $this->assertEventSequence([FlowFailed::class, UnsolicitedResponseReinitiated::class, FlowFailed::class]);
    }

    /**
     * A re-initiation locks the connection's row alone.
     *
     * @return void
     */
    public function testAReinitiationLocksTheConnectionAlone(): void
    {
        config()->set('sso.features.enforcement', true);

        $connection = $this->reinitiatingConnection();

        $this->script['answer'] = Reinitiation::allowed(self::START_URL, $this->record(300));
        $this->recordLockOrder();

        self::assertTrue($this->completeAtAssertionConsumerService($connection)->isReinitiated());
        self::assertSame(['connections ' . $connection->id], $this->lockOrder());
        self::assertSame(0, $this->enforcementStatements());
    }

    /**
     * Only the correlation step may hand a completion to re-initiation.
     *
     * @return void
     */
    public function testOnlyTheCorrelationStepHandsACompletionToReinitiation(): void
    {
        $request = $this->request();

        $this->app?->instance(ConsumeRequest::class, self::reinitiating());

        try {
            $this->completeAtCallback();
            self::fail('A consumption handing over to re-initiation completed.');
        } catch (\LogicException $e) {
            self::assertSame('Only the correlation step hands a completion to re-initiation, not the [consumption] step.', $e->getMessage());
        }

        $this->app?->forgetInstance(ConsumeRequest::class);
        $this->app?->instance(ResolveLink::class, self::reinitiating());

        try {
            $this->completeAtCallback();
            self::fail('A link resolution handing over to re-initiation completed.');
        } catch (\LogicException $e) {
            self::assertSame('Only the correlation step hands a completion to re-initiation, not the [link_resolution] step.', $e->getMessage());
        }

        self::assertNull($this->reread($request)->completed_at);
        $this->assertNoEvents();
    }

    /**
     * Only the provisioning step may stop at its boundary.
     *
     * @return void
     */
    public function testOnlyTheProvisioningStepStopsAtItsBoundary(): void
    {
        $request = $this->request();

        $this->app?->instance(ResolveLink::class, self::answering(static fn (CompletionState $state): StageOutcome => StageOutcome::provision($state)));

        try {
            $this->completeAtCallback();
            self::fail('A link resolution stopped at the provisioning boundary.');
        } catch (\LogicException $e) {
            self::assertSame('Only the provisioning step stops at its boundary, not the [link_resolution] step.', $e->getMessage());
        }

        self::assertNull($this->reread($request)->completed_at);
        $this->assertNoEvents();
    }

    /**
     * Rows of `[what the stage's state holds, the message]`.
     *
     * @return iterable<string, array{0: bool, 1: string}>
     */
    public static function provideHollowStates(): iterable
    {
        yield 'no application' => [false, 'A consumed completion holds its application.'];
        yield 'no connection' => [true, 'A consumed completion holds its connection.'];
    }

    /**
     * A state that lost what the completion consumed rolls back.
     *
     * @param  bool  $consumed
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideHollowStates')]
    public function testAStateThatLostWhatItConsumedIsAMisconfiguration(bool $consumed, string $message): void
    {
        $request = $this->request();

        $this->app?->instance(ResolveLink::class, self::answering(static function (CompletionState $state) use ($consumed): StageOutcome {

            $arrived = CompletionState::arrived($state->connectionId, $state->request, Clients::browser());
            $hollow  = $consumed ? $arrived->withAuthorizationRequest($state->authorizationRequest, $state->consumed, $state->application) : $arrived;

            return StageOutcome::refuse($hollow, FailureReason::UNLINKED);
        }));

        try {
            $this->completeAtCallback();
            self::fail('A hollow state was answered.');
        } catch (\LogicException $e) {
            self::assertSame($message, $e->getMessage());
        }

        self::assertNull($this->reread($request)->completed_at);
        $this->assertNoEvents();
    }

    /**
     * Re-initiation needs an unsolicited response at a re-initiating driver.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReinitiationNeedsAnUnsolicitedResponseAtAReinitiatingDriver(): void
    {
        $arrived = CompletionState::arrived($this->connection->id, new CompletionRequest('POST', '', []), Clients::browser());
        $read    = $arrived->withConnection($this->connection);
        $cases   = [
            ['Only an unsolicited response is re-initiated.', $read],
            ['Only an unsolicited response is re-initiated.', $read->withCorrelation(Correlation::solicited(self::STATE))],
            ['A re-initiated response holds its connection.', $arrived->withCorrelation(Correlation::unsolicited())],
            ['The [verifying] driver does not re-initiate an unsolicited response.', $read->withCorrelation(Correlation::unsolicited())],
        ];

        foreach ($cases as [$message, $state]) {
            try {
                app(UnsolicitedReinitiation::class)->run(Flow::ASSERTION, $state, app(RecordReplay::class));
                self::fail('A state that was not handed over was re-initiated.');
            } catch (\LogicException $e) {
                self::assertSame($message, $e->getMessage());
            }
        }

        $this->assertNoEvents();
    }

    /**
     * Spy on every step, recording its transaction level and answer.
     *
     * @return void
     */
    private function spyOnEveryStep(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        foreach (CompletionStep::cases() as $step) {

            $class = CompletionPipeline::stageClass($step);
            $stage = $app->make($class);

            $app->instance($class, new readonly class ($step, $stage, $this->ran, $this->answered) implements CompletionStage {
                /**
                 * Constructor.
                 *
                 * @param  \SineMacula\Laravel\Sso\Completion\Enums\CompletionStep  $step
                 * @param  \SineMacula\Laravel\Sso\Contracts\CompletionStage  $stage
                 * @param  \ArrayObject<int, array{0: string, 1: int}>  $ran
                 * @param  \ArrayObject<string, array{0: \SineMacula\Laravel\Sso\Completion\StageOutcome, 1: bool}>  $answered
                 */
                public function __construct(

                    /** The step spied on. */
                    private CompletionStep $step,

                    /** The stage registered for it. */
                    private CompletionStage $stage,

                    /** Each step run, with its transaction level. */
                    private \ArrayObject $ran,

                    /** What each step answered, and whether its request was completed when it ran. */
                    private \ArrayObject $answered,
                ) {}

                /**
                 * Record the step, run its stage and record what it answered.
                 *
                 * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
                 * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
                 */
                #[\Override]
                public function run(CompletionState $state): StageOutcome
                {
                    $this->ran->append([$this->step->value, DB::connection(StorageConnection::name())->transactionLevel()]);

                    $completed = $state->authorizationRequest?->completed_at !== null;
                    $outcome   = $this->stage->run($state);

                    $this->answered[$this->step->value] = [$outcome, $completed];

                    return $outcome;
                }
            });
        }
    }

    /**
     * What the step's spy answered, and whether its request was completed.
     *
     * @param  string  $step
     * @return array{0: \SineMacula\Laravel\Sso\Completion\StageOutcome, 1: bool}
     *
     * @throws \LogicException
     */
    private function spied(string $step): array
    {
        return $this->answered[$step] ?? throw new \LogicException("The [{$step}] step did not run.");
    }

    /**
     * The steps the spies ran, in order.
     *
     * @return list<string>
     */
    private function stepsRan(): array
    {
        return array_values(array_map(static fn (array $ran): string => $ran[0], $this->ran->getArrayCopy()));
    }

    /**
     * The status, reason, redirect URI and reference of the result.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return list<?string>
     */
    private static function summary(CompletionResult $result): array
    {
        return [$result->status->value, $result->reason?->value, $result->redirectUri, $result->reference?->value];
    }

    /**
     * Complete at the callback with the state.
     *
     * @param  string  $state
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \LogicException
     */
    private function completeAtCallback(string $state = self::STATE): CompletionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(CompletionService::class)->complete(
            CompletionEndpoint::CALLBACK,
            $this->connection->id,
            new CompletionRequest('GET', 'state=' . $state, []),
            Clients::browser(),
        );
    }

    /**
     * Store a `sign_in` request for `web` unless the attributes say otherwise.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function request(array $attributes = []): AuthorizationRequest
    {
        return $this->makeAuthorizationRequest($this->connection, $attributes + [
            'reference'         => self::REFERENCE,
            'state_digest'      => hash('sha256', self::STATE),
            'handoff_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_verifier'     => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-piped-request-0123'),
        ]);
    }

    /**
     * The request, read again.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function reread(AuthorizationRequest $request): AuthorizationRequest
    {
        return AuthorizationRequest::query()->whereKey($request->id)->sole();
    }

    /**
     * An enforcement stage that refuses every state, recording that it ran.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Sso\Contracts\CompletionStage
     */
    private function refusing(FailureReason $reason): CompletionStage
    {
        $ran = $this->ran;

        return new readonly class ($reason, $ran) implements CompletionStage {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
             * @param  \ArrayObject<int, array{0: string, 1: int}>  $ran
             */
            public function __construct(

                /** The reason every state is refused for. */
                private FailureReason $reason,

                /** Each step run, with its transaction level. */
                private \ArrayObject $ran,
            ) {}

            /**
             * Refuse the state.
             *
             * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
             * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
             */
            #[\Override]
            public function run(CompletionState $state): StageOutcome
            {
                $this->ran->append(['enforcement', DB::connection(StorageConnection::name())->transactionLevel()]);

                return StageOutcome::refuse($state, $this->reason);
            }
        };
    }

    /**
     * A connection whose driver re-initiates every response as scripted.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function reinitiatingConnection(): Connection
    {
        $script = $this->script;

        $script['start_url'] = self::START_URL;

        app(ProtocolManager::class)->extend(self::REINITIATING, fn (): ProtocolDriver => new readonly class ($script) implements ProtocolDriver, ReinitiatingDriver {
            /**
             * Constructor.
             *
             * @param  \ArrayObject<string, mixed>  $script
             */
            public function __construct(

                /** What the driver answers, and what it runs first. */
                private \ArrayObject $script,
            ) {}

            /**
             * The example settings the values give.
             *
             * @param  array<array-key, mixed>  $values
             * @return \SineMacula\Laravel\Sso\Contracts\ProtocolSettings
             */
            #[\Override]
            public function settings(array $values): ProtocolSettings
            {
                return ExampleSettings::fromArray($values);
            }

            /**
             * Complete once the issuer is set.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return bool
             */
            #[\Override]
            public function isComplete(SsoConnection $connection): bool
            {
                return ExampleSettings::fromArray($connection->getSettings())->isComplete();
            }

            /**
             * Start nothing.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
             * @return \SineMacula\Laravel\Sso\Protocols\Start
             */
            #[\Override]
            public function start(SsoConnection $connection, StartRequest $request): Start
            {
                unset($connection, $request);

                return Start::refused(FailureReason::CONNECTION_UNAVAILABLE);
            }

            /**
             * Read every response as unsolicited.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
             * @return \SineMacula\Laravel\Sso\Protocols\Correlation
             */
            #[\Override]
            public function correlate(SsoConnection $connection, CompletionRequest $request): Correlation
            {
                unset($connection, $request);

                return Correlation::unsolicited();
            }

            /**
             * Refuse every solicited response.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
             * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Protocols\Completion
             */
            #[\Override]
            public function complete(SsoConnection $connection, CompletionRequest $request, ConsumedRequest $consumed, ClientContext $client): Completion
            {
                unset($connection, $request, $consumed);

                return Completion::refused(FailureReason::REQUEST_UNKNOWN);
            }

            /**
             * An empty JSON document.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
             */
            #[\Override]
            public function describe(SsoConnection $connection): ServiceProviderDescription
            {
                unset($connection);

                return ServiceProviderDescription::document('application/json', '{}');
            }

            /**
             * Run the script's change once, if any, then answer as scripted.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
             * @return \SineMacula\Laravel\Sso\Protocols\Reinitiation
             *
             * @throws \LogicException
             */
            #[\Override]
            public function reinitiate(SsoConnection $connection, CompletionRequest $request): Reinitiation
            {
                unset($connection, $request);

                $change = $this->script['change'] ?? null;

                unset($this->script['change']);

                if ($change instanceof \Closure) {
                    $change();
                }

                $answer = $this->script['answer'] ?? null;

                return $answer instanceof Reinitiation ? $answer : throw new \LogicException('The script holds no re-initiation.');
            }

            /**
             * The script's start URL, `null` when it holds none.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return ?string
             */
            #[\Override]
            public function startUrl(SsoConnection $connection): ?string
            {
                unset($connection);

                $startUrl = $this->script['start_url'] ?? null;

                return is_string($startUrl) ? $startUrl : null;
            }
        });

        return $this->makeConnection(['protocol' => self::REINITIATING, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
    }

    /**
     * Complete at the assertion consumer service with an unread post.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function completeAtAssertionConsumerService(Connection $connection): CompletionResult
    {
        return app(CompletionService::class)->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $connection->id,
            new CompletionRequest('POST', '', ['SAMLResponse' => 'unread']),
            Clients::browser(),
        );
    }

    /**
     * Make what a refresh applied lapse a minute after now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $limit
     * @return void
     */
    private function lapseInAMinute(Connection $connection, string $limit): void
    {
        $now = $this->clock->now();

        $connection->forceFill(match ($limit) {
            'valid_until' => ['metadata_fetched_at' => $now->subHour(), 'metadata_valid_until' => $now->addMinute()],
            default       => ['metadata_fetched_at' => $now->subSeconds(MetadataSettings::DEFAULT_STALE_LIMIT_SECONDS - 60), 'metadata_valid_until' => null],
        })->save();
    }

    /**
     * A replay record of one assertion, until the seconds given after now.
     *
     * @param  int  $seconds
     * @return \SineMacula\Laravel\Sso\Protocols\ReplayRecord
     */
    private function record(int $seconds): ReplayRecord
    {
        return ReplayRecord::samlAssertion('reinitiating-connection', VerifyingDriver::ISSUER, '_assertion-reinitiated', $this->clock->now()->addSeconds($seconds));
    }

    /**
     * The connection, tenant and protocol the context names.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @return list<?string>
     */
    private static function contextOf(EventContext $context): array
    {
        self::assertSame([null, null, null, null, null], [$context->application, $context->purpose, $context->requestReference, $context->identityId, $context->sessionId]);

        return [$context->connectionId, $context->connectionTenantId, $context->protocol];
    }

    /**
     * A stage that answers whatever the callback does with the state.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Completion\CompletionState): \SineMacula\Laravel\Sso\Completion\StageOutcome  $answer
     * @return \SineMacula\Laravel\Sso\Contracts\CompletionStage
     */
    private static function answering(\Closure $answer): CompletionStage
    {
        return new readonly class ($answer) implements CompletionStage {
            /**
             * Constructor.
             *
             * @param  \Closure(\SineMacula\Laravel\Sso\Completion\CompletionState): \SineMacula\Laravel\Sso\Completion\StageOutcome  $answer
             */
            public function __construct(

                /** What the stage answers. */
                private \Closure $answer,
            ) {}

            /**
             * Answer the state.
             *
             * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
             * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
             */
            #[\Override]
            public function run(CompletionState $state): StageOutcome
            {
                return ($this->answer)($state);
            }
        };
    }

    /**
     * A stage that hands every state to re-initiation.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\CompletionStage
     */
    private static function reinitiating(): CompletionStage
    {
        return new readonly class implements CompletionStage {
            /**
             * Hand the state to re-initiation.
             *
             * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
             * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
             */
            #[\Override]
            public function run(CompletionState $state): StageOutcome
            {
                return StageOutcome::reinitiate($state);
            }
        };
    }

    /**
     * A linking contract that links every result to one identity.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\Linker
     */
    private static function linker(): Linker
    {
        return new readonly class implements Linker {
            /**
             * The one identity.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
            {
                unset($result);

                return ExampleLinks::resolution(new IdentityReference('App\Models\User', '42'));
            }
        };
    }
}
