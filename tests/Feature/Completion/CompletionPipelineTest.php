<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionStep;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Completion\Stages\CheckEnforcement;
use SineMacula\Laravel\Sso\Completion\Stages\ConsumeRequest;
use SineMacula\Laravel\Sso\Completion\Stages\CorrelateResponse;
use SineMacula\Laravel\Sso\Completion\Stages\DecideUnlinked;
use SineMacula\Laravel\Sso\Completion\Stages\DomainReservation;
use SineMacula\Laravel\Sso\Completion\Stages\IssueHandoff;
use SineMacula\Laravel\Sso\Completion\Stages\Provisioning;
use SineMacula\Laravel\Sso\Completion\Stages\ResolveLink;
use SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\RedirectUriResolver;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\RecordsLockOrder;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesEnforcement;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Enforcement\ScriptedInheritance;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Feature tests for the completion pipeline (SSO-5.6, SSO-8.6, SSO-11.3,
 * SSO-11.4): a stage for each step, run in exactly `CompletionStep::cases()`'s
 * order; the first three outside any transaction and every locked one inside
 * one; a refusal ending the pipeline; the request's `completed_at` set whether
 * it completed or was refused; a request voided, or a connection disabled or
 * gone, while the response was validated, refused under the lock; and a
 * misconfiguration that propagates and rolls the completion back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionPipeline::class)]
final class CompletionPipelineTest extends TestCase
{
    use RecordsEventSequences, RecordsLockOrder, UsesConnections, UsesDomains, UsesEnforcement, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-piped-request-0001';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Pq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

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

    /**
     * Bind a fixed clock, the recording issuer and a linker, register the
     * application and the driver, and create the tables and a usable
     * connection.
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

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(HandoffIssuer::class, $this->issuer);
        $this->app?->instance(Linker::class, self::linker());
        $this->app?->instance('request', Request::create('/auth/sso/connections/x/callback', 'GET', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        $this->createEnforcementTable();
        self::migration(self::SINGLE_USE_MIGRATION)->up(); // @phpstan-ignore method.notFound
        self::migration(self::RATE_LIMITS_MIGRATION)->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection([
            'protocol' => VerifyingDriver::NAME,
            'enabled'  => true,
            'settings' => ['issuer' => VerifyingDriver::ISSUER],
        ]);

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
        self::migration(self::RATE_LIMITS_MIGRATION)->down(); // @phpstan-ignore method.notFound
        self::migration(self::SINGLE_USE_MIGRATION)->down(); // @phpstan-ignore method.notFound
        $this->dropEnforcementTable();
        $this->dropDomainsTable();
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
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
            'link_resolution'    => ResolveLink::class,
            'enforcement'        => CheckEnforcement::class,
            'domain_reservation' => DomainReservation::class,
            'provisioning'       => Provisioning::class,
            'unlinked_decision'  => DecideUnlinked::class,
            'handoff_issuance'   => IssueHandoff::class,
        ], $stages);
    }

    /**
     * The stages run in exactly the steps' order: the first three outside any
     * transaction, every locked one inside the one transaction, before the
     * request is marked completed.
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
            [0, 0, 0, 1, 1, 1, 1, 1, 1],
            array_map(static fn (array $ran): int => $ran[1], $this->ran->getArrayCopy()),
        );
        self::assertFalse($this->spied('handoff_issuance')[1]);
        self::assertNotNull($this->reread($request)->completed_at);
    }

    /**
     * The locked stages are given the connection's and the request's rows as
     * they were locked, not as they were read before.
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
     * A refusal ends the pipeline: a refused response runs no locked stage, and
     * a locked stage's refusal runs none after it.
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
        self::assertSame(['correlation', 'consumption', 'validation', 'link_resolution', 'enforcement'], $this->stepsRan());
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * The request's `completed_at` is set when it completes, when its response
     * is refused and when its consumption is refused; a response that matches
     * no request marks nothing.
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
     * A request a change to its connection voided while its response was
     * validated is refused under the lock with `connection_unavailable`,
     * redirected, with no locked stage run and no code issued.
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
     * A connection disabled while the response was validated is refused under
     * the lock with `connection_unavailable`, and issues nothing.
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
     * A connection whose row went while the response was validated is refused
     * under the lock, and its request still marked completed; a request whose
     * row went is refused too, with nothing to mark.
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
     * With the feature on, the locked steps' transaction locks the tenant's
     * enforcement row first (an upsert, then a locking read), then the
     * connection and the rule's connections in one statement in ascending id
     * order, then the request; the enforcement step judges the policy the
     * locked rows give, carried on the state, with no further read of the rule,
     * and the handoff carries its version.
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
        self::assertSame($rule->version, $this->issuer->grants()[0]->enforcementVersion);
    }

    /**
     * Under a rule the connection does not satisfy, the locked policy refuses
     * with `enforcement_unsatisfied`, redirected, with no code issued.
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
     * A tenant with no rule stored is locked through an unconfigured row that
     * requires nothing; the handoff carries no enforcement version.
     *
     * @return void
     */
    public function testATenantWithNoRuleIsLockedThroughAnUnconfiguredRow(): void
    {
        config()->set('sso.features.enforcement', true);

        $this->request();

        self::assertTrue($this->completeAtCallback()->isCompleted());
        self::assertNull(TenantEnforcement::query()->sole()->version);
        self::assertNull($this->issuer->grants()[0]->enforcementVersion);
    }

    /**
     * With the feature off, the locked steps lock the connection and then the
     * request: no statement names the enforcement table, no row is inserted,
     * and the inheritance contract is never asked; nor is it for a completion
     * already refused with the feature on.
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
     * An inheritance contract that names another enforcing tenant under the
     * lock than when it was taken refuses with `connection_unavailable`,
     * running no locked step and issuing nothing; the request is still marked
     * completed.
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
     * A step whose stage resolves to something else is a misconfiguration: it
     * propagates, rolls the completion back and reports nothing.
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
     * A redirect URI resolver that answers what no redirect URI may be is a
     * misconfiguration: it propagates, the completion rolls back with its code,
     * and nothing is reported.
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
     * Spy on every step, recording the transaction level each ran at, then
     * running the stage registered for it and recording what it answered.
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
                 * Record the step, run its stage and record what it answered,
                 * and whether its request was completed when it ran.
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
     * What the spy of the step answered, and whether its request was completed
     * when it ran.
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

        return $app->make(CompletionService::class)->callback($this->connection->id, new CompletionRequest('GET', 'state=' . $state, []));
    }

    /**
     * Store a `sign_in` request for `web` through the connection, started with
     * the state and the reference, unless the attributes say otherwise.
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
     * A stage for the enforcement step that refuses every state for the reason,
     * recording that it ran.
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
             * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
             */
            #[\Override]
            public function resolve(VerifiedResult $result): IdentityReference
            {
                unset($result);

                return new IdentityReference('App\Models\User', '42');
            }
        };
    }

    /**
     * The shipped migration of the file.
     *
     * @param  string  $file
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function migration(string $file): Migration
    {
        return require dirname(__DIR__, 3) . $file;
    }
}
