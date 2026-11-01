<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion\Stages;

use Carbon\CarbonImmutable;
use Illuminate\Database\Migrations\Migration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\ApplicationRegistry;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\ResultBuilder;
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
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Feature tests for each completion stage alone (SSO-5.6, SSO-8.6, SSO-9.2,
 * SSO-4.6, SSO-6.10): what each goes on with, what each refuses and why, and
 * the `LogicException` of a stage run before the steps it needs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CorrelateResponse::class)]
#[CoversClass(ConsumeRequest::class)]
#[CoversClass(ValidateResponse::class)]
#[CoversClass(ResolveLink::class)]
#[CoversClass(CheckEnforcement::class)]
#[CoversClass(DecideUnlinked::class)]
#[CoversClass(IssueHandoff::class)]
final class StagesTest extends TestCase
{
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-staged-request-001';

    /** @var string The nonce the request was started with. */
    private const string NONCE = 'the-nonce-of-the-staged-request-0123456789';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var string The client's S256 challenge the request keeps. */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Protocols\VerifyingDriver The driver the connection runs over. */
    private VerifyingDriver $driver;

    /** @var \Tests\Fixtures\Handoffs\RecordingHandoffIssuer The handoff issuer. */
    private RecordingHandoffIssuer $issuer;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /** @var list<array{0: string, 1: string}> Each tenant and application the enforcement was asked about. */
    private array $enforcementAsked = [];

    /** @var int How many times the deadline contract was asked. */
    private int $deadlineAsked = 0;

    /** @var int How many requests have taken a reference of their own. */
    private int $references = 0;

    /**
     * Bind a fixed clock and the recording issuer, register the applications
     * and the driver, and create the tables and a usable connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock  = new FixedClock('2026-11-01T09:30:00Z');
        $this->driver = new VerifyingDriver;
        $this->issuer = new RecordingHandoffIssuer;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(HandoffIssuer::class, $this->issuer);

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', [
            'web'    => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
            'native' => ['redirect_uri' => 'com.example.app:/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true, 'handoff_ttl_seconds' => 120],
        ]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::singleUseMigration()->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection([
            'protocol'          => VerifyingDriver::NAME,
            'enabled'           => true,
            'settings'          => ['issuer' => VerifyingDriver::ISSUER],
            'attribute_mapping' => ['email' => 'mail'],
        ]);
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
     * Correlation goes on with a solicited correlation, the rest of the state
     * kept.
     *
     * @return void
     */
    public function testCorrelationGoesOnWithASolicitedResponse(): void
    {
        $state   = $this->arrived();
        $outcome = $this->stage(CorrelateResponse::class)->run($state);

        self::assertTrue($outcome->isProceeding());
        self::assertSame(hash('sha256', self::STATE), $outcome->state->correlation?->stateDigest());
        self::assertSame($state->connection, $outcome->state->connection);
        self::assertSame(1, $this->driver->correlations());
    }

    /**
     * Correlations that name no request.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Protocols\Correlation}>
     */
    public static function provideUnmatchedCorrelations(): iterable
    {
        yield 'unsolicited' => [Correlation::unsolicited()];
        yield 'uncorrelated' => [Correlation::uncorrelated()];
    }

    /**
     * Correlation refuses an unsolicited and an uncorrelated response with
     * `request_unknown`, with no trusted redirect target.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @return void
     */
    #[DataProvider('provideUnmatchedCorrelations')]
    public function testCorrelationRefusesAResponseThatNamesNoRequest(Correlation $correlation): void
    {
        $this->driver->correlation = $correlation;

        $state   = $this->arrived();
        $outcome = $this->stage(CorrelateResponse::class)->run($state);

        self::assertSame(FailureReason::REQUEST_UNKNOWN, $outcome->reason);
        self::assertSame($state, $outcome->state);
        self::assertFalse($outcome->state->hasRedirectTarget());
    }

    /**
     * Consumption goes on with the consumed request, what the driver is given
     * of it and its application.
     *
     * @return void
     */
    public function testConsumptionGoesOnWithTheConsumedRequest(): void
    {
        $request = $this->request();
        $outcome = $this->stage(ConsumeRequest::class)->run($this->correlated());

        self::assertTrue($outcome->isProceeding());
        self::assertTrue($outcome->state->hasRedirectTarget());
        self::assertSame($request->id, $outcome->state->authorizationRequest?->id);
        self::assertSame(self::REFERENCE, $outcome->state->consumed?->reference->value);
        self::assertSame('the-pkce-verifier-of-the-staged-request-012', $outcome->state->consumed->codeVerifier()?->reveal());
        self::assertTrue($outcome->state->consumed->isNonce(self::NONCE));
        self::assertSame('web', $outcome->state->application?->name);
        self::assertNotNull(AuthorizationRequest::query()->whereKey($request->id)->sole()->consumed_at);
    }

    /**
     * A consumed request refused with its application still registered keeps
     * the request and the application, so the completion redirects, but never
     * its nonce digest or PKCE verifier.
     *
     * @return void
     */
    public function testARefusedConsumptionKeepsItsTargetButNoSecret(): void
    {
        $request = $this->request(['expires_at' => $this->clock->now(), 'expected_issuer' => VerifyingDriver::ISSUER, 'issuer_required' => true]);
        $outcome = $this->stage(ConsumeRequest::class)->run($this->correlated());

        self::assertSame(FailureReason::REQUEST_EXPIRED, $outcome->reason);
        self::assertTrue($outcome->state->hasRedirectTarget());
        self::assertSame($request->id, $outcome->state->authorizationRequest?->id);
        self::assertSame('web', $outcome->state->application?->name);

        $consumed = $outcome->state->consumed;

        self::assertNotNull($consumed);
        self::assertSame(Purpose::SIGN_IN, $consumed->purpose);
        self::assertSame('web', $consumed->application);
        self::assertSame(self::REFERENCE, $consumed->reference->value);
        self::assertSame('2026-11-01T09:30:00+00:00', $consumed->startedAt->toIso8601String());
        self::assertSame(VerifyingDriver::ISSUER, $consumed->expectedIssuer);
        self::assertTrue($consumed->issuerRequired);
        self::assertSame('_request-1', $consumed->samlRequestId);
        self::assertNull($consumed->codeVerifier());
        self::assertFalse($consumed->isNonce(self::NONCE));
    }

    /**
     * A consumed request whose application is no longer registered is refused
     * with `application_not_allowed`, with no trusted redirect target.
     *
     * @return void
     */
    public function testARefusedConsumptionWithNoApplicationHasNoTarget(): void
    {
        $this->request(['application' => 'retired']);

        $state   = $this->correlated();
        $outcome = $this->stage(ConsumeRequest::class)->run($state);

        self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $outcome->reason);
        self::assertSame($state, $outcome->state);
    }

    /**
     * A state no request has, and a replay, are refused with `request_unknown`,
     * with no trusted redirect target.
     *
     * @return void
     */
    public function testAnUnknownOrReplayedRequestIsRefusedWithNoTarget(): void
    {
        $state = $this->correlated();

        $unknown = $this->stage(ConsumeRequest::class)->run($state);

        $this->request();

        $this->stage(ConsumeRequest::class)->run($state);

        $replayed = $this->stage(ConsumeRequest::class)->run($state);

        foreach ([$unknown, $replayed] as $outcome) {
            self::assertSame(FailureReason::REQUEST_UNKNOWN, $outcome->reason);
            self::assertSame($state, $outcome->state);
        }
    }

    /**
     * Validation goes on with the claims the driver verified and the result
     * built from them.
     *
     * @return void
     */
    public function testValidationGoesOnWithTheClaimsAndTheResult(): void
    {
        $state   = $this->consumed();
        $outcome = $this->stage(ValidateResponse::class)->run($state);

        self::assertTrue($outcome->isProceeding());
        self::assertSame(VerifyingDriver::SUBJECT, $outcome->state->claims?->subject);
        self::assertSame(VerifyingDriver::SUBJECT, $outcome->state->result?->subject);
        self::assertSame(['email' => 'person@example.com'], $outcome->state->result->attributes);
        self::assertSame([$state->consumed], $this->driver->completions());
    }

    /**
     * Validation refuses a response the driver refuses, with its reason.
     *
     * @return void
     */
    public function testValidationRefusesWithTheDriversReason(): void
    {
        $this->driver->refusal = FailureReason::AUDIENCE_MISMATCH;

        $state   = $this->consumed();
        $outcome = $this->stage(ValidateResponse::class)->run($state);

        self::assertSame(FailureReason::AUDIENCE_MISMATCH, $outcome->reason);
        self::assertSame($state, $outcome->state);
    }

    /**
     * Validation refuses a connection that is no longer usable with
     * `connection_unavailable`, without asking its driver.
     *
     * @return void
     */
    public function testValidationRefusesAnUnusableConnectionWithoutAskingTheDriver(): void
    {
        $this->connection->forceFill(['enabled' => false])->save();

        $state   = $this->consumed();
        $outcome = $this->stage(ValidateResponse::class)->run($state);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $outcome->reason);
        self::assertSame($state, $outcome->state);
        self::assertSame([], $this->driver->completions());
    }

    /**
     * Link resolution goes on with the identity the linker resolves, and with
     * the state as it was when it resolves none.
     *
     * @return void
     */
    public function testLinkResolutionGoesOnWithTheIdentityResolved(): void
    {
        $identity = new IdentityReference('App\Models\User', '42');
        $state    = $this->verified();

        $this->app?->instance(Linker::class, self::linker($identity));

        $linked = $this->stage(ResolveLink::class)->run($state);

        $this->app?->instance(Linker::class, self::linker(null));

        $unlinked = $this->stage(ResolveLink::class)->run($state);

        self::assertTrue($linked->isProceeding());
        self::assertSame($identity, $linked->state->linkedIdentity);
        self::assertTrue($unlinked->isProceeding());
        self::assertSame($state, $unlinked->state);
    }

    /**
     * Enforcement refuses a required policy the connection does not satisfy,
     * and goes on with the version of one it satisfies, or of one that requires
     * nothing; asked for the connection's tenant and the application.
     *
     * @return void
     */
    public function testEnforcementRefusesAnUnsatisfiedPolicyAndKeepsTheVersion(): void
    {
        $state = $this->verified();

        $outcomes = [];
        $policies = [
            EnforcementPolicy::required('tenant-1', 'tenant-1', [$this->connection->id], 'version-1'),
            EnforcementPolicy::required('tenant-1', 'tenant-1', ['another'], 'version-2'),
            EnforcementPolicy::notRequired('tenant-1', 'tenant-1', 'version-3'),
            EnforcementPolicy::notRequired('tenant-1', 'tenant-1'),
        ];

        foreach ($policies as $policy) {

            $this->bindEnforcement($policy);

            $outcomes[] = $this->stage(CheckEnforcement::class)->run($state);
        }

        self::assertSame([null, 'enforcement_unsatisfied', null, null], array_map(static fn (StageOutcome $outcome): ?string => $outcome->reason?->value, $outcomes));
        self::assertSame(['version-1', null, 'version-3', null], array_map(static fn (StageOutcome $outcome): ?string => $outcome->state->enforcementVersion, $outcomes));
        self::assertSame($state, $outcomes[1]->state);
        self::assertSame($state, $outcomes[3]->state);
        self::assertSame(array_fill(0, 4, ['tenant-1', 'web']), $this->enforcementAsked);
    }

    /**
     * The purpose, the application, whether the result is linked, and the
     * reason the decision refuses with, if any.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: string, 2: bool, 3: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideUnlinkedDecisions(): iterable
    {
        yield 'an unlinked sign_in' => [Purpose::SIGN_IN, 'web', false, FailureReason::UNLINKED];
        yield 'an unlinked sign_in allowed unlinked handoffs' => [Purpose::SIGN_IN, 'native', false, null];
        yield 'a linked sign_in' => [Purpose::SIGN_IN, 'web', true, null];
        yield 'an unlinked link' => [Purpose::LINK, 'web', false, null];
        yield 'an unlinked reauthenticate' => [Purpose::REAUTHENTICATE, 'web', false, null];
    }

    /**
     * An unlinked `sign_in` is refused with `unlinked` unless its application
     * allows unlinked handoffs; a linked `sign_in`, and an unlinked `link` or
     * `reauthenticate`, pass unchanged.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  bool  $linked
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideUnlinkedDecisions')]
    public function testTheUnlinkedDecision(Purpose $purpose, string $application, bool $linked, ?FailureReason $reason): void
    {
        $state = $this->verified($purpose, $application);
        $state = $linked ? $state->withLinkedIdentity(new IdentityReference('App\Models\User', '42')) : $state;

        $outcome = $this->stage(DecideUnlinked::class)->run($state);

        self::assertSame($reason, $outcome->reason);
        self::assertSame($state, $outcome->state);
    }

    /**
     * Issuance goes on with the handoff issued for a grant of every part of the
     * state.
     *
     * @return void
     */
    public function testIssuanceIssuesTheHandoffForTheGrant(): void
    {
        $linked = new IdentityReference('App\Models\User', '42');
        $state  = $this->verified(Purpose::REAUTHENTICATE, 'native')->withLinkedIdentity($linked)->withEnforcementVersion('version-4');

        $outcome = $this->stage(IssueHandoff::class)->run($state);

        self::assertTrue($outcome->isProceeding());
        self::assertSame($this->issuer->issued()[0], $outcome->state->handoff);

        $grant = $this->issuer->soleGrant();

        self::assertSame($state->result, $grant->result);
        self::assertSame(self::CHALLENGE, $grant->challenge->value);
        self::assertSame('2026-11-01T09:32:00+00:00', $grant->expiresAt->toIso8601String());
        self::assertSame($linked, $grant->linkedIdentity);
        self::assertSame(['type' => 'App\Models\User', 'id' => '7'], $grant->identity?->jsonSerialize());
        self::assertSame('session-7', $grant->sessionId);
        self::assertSame('version-4', $grant->enforcementVersion);
        self::assertSame('2026-11-01T18:00:00+00:00', $grant->sessionNotAfter?->toIso8601String());
        self::assertSame('2026-11-01T18:00:00+00:00', $outcome->state->sessionNotAfter?->toIso8601String());
    }

    /**
     * Issuance refuses an application the policy no longer allows with
     * `application_not_allowed`, and issues nothing.
     *
     * @return void
     */
    public function testIssuanceRefusesAnApplicationNoLongerAllowed(): void
    {
        config()->set('sso.applications.web.external_sign_in', false);

        $state   = $this->verified();
        $outcome = $this->stage(IssueHandoff::class)->run($state);

        self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $outcome->reason);
        self::assertSame($state, $outcome->state);
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * A deadline the contract ignores sets no latest end, and a result with no
     * deadline never asks the contract.
     *
     * @return void
     */
    public function testIssuanceAsksTheDeadlineContractOnlyForADeadline(): void
    {
        $this->bindDeadline(DeadlineEffect::IGNORED);

        $ignored = $this->stage(IssueHandoff::class)->run($this->verified());

        self::assertNull($ignored->state->sessionNotAfter);
        self::assertNull($this->issuer->grants()[0]->sessionNotAfter);
        self::assertSame(1, $this->deadlineAsked);

        $this->bindDeadline(DeadlineEffect::LIMITS_SESSION);

        $none = $this->stage(IssueHandoff::class)->run($this->verified(claims: new VerifiedClaims(VerifyingDriver::ISSUER, 'sub-1', null, [], new AuthenticationContext)));

        self::assertNull($none->state->sessionNotAfter);
        self::assertSame(0, $this->deadlineAsked);
    }

    /**
     * The seams of linking by a verified domain and provisioning pass every
     * state on unchanged.
     *
     * @return void
     */
    public function testTheUnbuiltStepsPassTheStateOn(): void
    {
        $state = $this->verified();

        foreach ([DomainReservation::class, Provisioning::class] as $class) {

            $outcome = $this->stage($class)->run($state);

            self::assertTrue($outcome->isProceeding());
            self::assertSame($state, $outcome->state);
        }
    }

    /**
     * Each stage, and what it says it needs.
     *
     * @return iterable<string, array{0: class-string<\SineMacula\Laravel\Sso\Contracts\CompletionStage>, 1: string}>
     */
    public static function provideStagesRunTooEarly(): iterable
    {
        yield 'correlation' => [CorrelateResponse::class, 'A response is correlated once its connection is read.'];
        yield 'consumption' => [ConsumeRequest::class, 'A request is consumed once its connection is read.'];
        yield 'validation' => [ValidateResponse::class, 'A response is validated once its connection is read.'];
        yield 'link resolution' => [ResolveLink::class, 'A link is resolved once the result is verified.'];
        yield 'enforcement' => [CheckEnforcement::class, 'Enforcement is checked once the connection is read.'];
        yield 'unlinked decision' => [DecideUnlinked::class, 'An unlinked result is decided once the request is consumed.'];
        yield 'issuance' => [IssueHandoff::class, 'A handoff is issued once the request is consumed.'];
    }

    /**
     * Each stage run before the steps it needs is the pipeline's mistake.
     *
     * @param  class-string<\SineMacula\Laravel\Sso\Contracts\CompletionStage>  $class
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideStagesRunTooEarly')]
    public function testAStageRunTooEarlyThrows(string $class, string $message): void
    {
        $this->app?->instance(Linker::class, self::linker(null));

        $state = CompletionState::arrived($this->connection->id, new CompletionRequest('GET', '', []));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage($message);

        $this->stage($class)->run($state);
    }

    /**
     * A stage that needs more than the connection says so too, when given only
     * the connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStageGivenOnlyTheConnectionSaysWhatItNeeds(): void
    {
        $messages = [];

        foreach ([app(ConsumeRequest::class), app(ValidateResponse::class), app(CheckEnforcement::class)] as $stage) {
            try {
                $stage->run($this->arrived());
            } catch (\LogicException $e) {
                $messages[] = $e->getMessage();
            }
        }

        self::assertSame([
            'A request is consumed once the response is correlated.',
            'A response is validated once its request is consumed.',
            'Enforcement is checked once the request is consumed.',
        ], $messages);
    }

    /**
     * Link resolution and issuance given a consumed request but no verified
     * result say they need one.
     *
     * @return void
     */
    public function testAStageGivenNoResultSaysItNeedsOne(): void
    {
        $this->app?->instance(Linker::class, self::linker(null));

        $messages = [];

        foreach ([app(ResolveLink::class), app(IssueHandoff::class)] as $stage) {
            try {
                $stage->run($this->consumed());
            } catch (\LogicException $e) {
                $messages[] = $e->getMessage();
            }
        }

        self::assertSame(['A link is resolved once the result is verified.', 'A handoff is issued once the result is verified.'], $messages);
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * The stage of the class, resolved from the container.
     *
     * @param  class-string<\SineMacula\Laravel\Sso\Contracts\CompletionStage>  $class
     * @return \SineMacula\Laravel\Sso\Contracts\CompletionStage
     */
    private function stage(string $class): CompletionStage
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make($class);
    }

    /**
     * The state of a callback carrying the state, with the connection read.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private function arrived(): CompletionState
    {
        return CompletionState::arrived($this->connection->id, new CompletionRequest('GET', 'state=' . self::STATE, []))->withConnection($this->connection);
    }

    /**
     * The state once the response is correlated by its state.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private function correlated(): CompletionState
    {
        return $this->arrived()->withCorrelation(Correlation::solicited(self::STATE));
    }

    /**
     * The state once a request for the purpose and the application is consumed:
     * a `link` for its identity, a `reauthenticate` for its identity on its
     * session.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private function consumed(Purpose $purpose = Purpose::SIGN_IN, string $application = 'web'): CompletionState
    {
        $binding = match ($purpose) {
            Purpose::SIGN_IN        => [],
            Purpose::LINK           => ['identity_type' => 'App\Models\User', 'identity_id' => '7'],
            Purpose::REAUTHENTICATE => ['identity_type' => 'App\Models\User', 'identity_id' => '7', 'session_id' => 'session-7'],
        };

        $request = $this->request([
            'purpose'         => $purpose,
            'application'     => $application,
            'reference'       => $this->nextReference(),
            'state_digest'    => hash('sha256', 'the-state-of-the-consumed-request-' . $this->references),
            'saml_request_id' => null,
        ] + $binding);

        $consumed = new ConsumedRequest($purpose, $application, RequestReference::fromString(self::REFERENCE), CarbonImmutable::parse('2026-11-01T09:29:00Z'));

        return $this->correlated()->withAuthorizationRequest($request, $consumed, self::application($application));
    }

    /**
     * The state once the response is verified, with the claims given or the
     * driver's.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  ?\SineMacula\Laravel\Sso\Results\VerifiedClaims  $claims
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private function verified(Purpose $purpose = Purpose::SIGN_IN, string $application = 'web', ?VerifiedClaims $claims = null): CompletionState
    {
        $state = $this->consumed($purpose, $application);
        $claims ??= VerifyingDriver::claims();

        /** @var \SineMacula\Laravel\Sso\Protocols\ConsumedRequest $consumed */
        $consumed = $state->consumed;

        return $state->withClaims($claims)->withResult(app(ResultBuilder::class)->build($claims, $this->connection, $consumed));
    }

    /**
     * Store a `sign_in` request for `web` through the connection, started with
     * the state, the nonce, the reference, the challenge and a PKCE verifier,
     * unless the attributes say otherwise.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function request(array $attributes = []): AuthorizationRequest
    {
        return $this->makeAuthorizationRequest($this->connection, $attributes + [
            'reference'         => self::REFERENCE,
            'state_digest'      => hash('sha256', self::STATE),
            'nonce_digest'      => hash('sha256', self::NONCE),
            'saml_request_id'   => '_request-1',
            'handoff_challenge' => self::CHALLENGE,
            'code_verifier'     => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-staged-request-012'),
        ]);
    }

    /**
     * Bind an enforcement contract that answers the policy, recording what it
     * is asked.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @return void
     */
    private function bindEnforcement(EnforcementPolicy $policy): void
    {
        $answer = function (string $tenantId, string $application) use ($policy): EnforcementPolicy {
            $this->enforcementAsked[] = [$tenantId, $application];

            return $policy;
        };

        $this->app?->instance(Enforcement::class, new readonly class ($answer) implements Enforcement {
            /**
             * Constructor.
             *
             * @param  \Closure(string, string): \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $answer
             */
            public function __construct(

                /** What every question is answered. */
                private \Closure $answer,
            ) {}

            /**
             * The policy given.
             *
             * @param  string  $tenantId
             * @param  string  $application
             * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
             */
            #[\Override]
            public function policy(string $tenantId, string $application): EnforcementPolicy
            {
                return ($this->answer)($tenantId, $application);
            }
        });
    }

    /**
     * Bind a deadline contract that answers the effect, counting from zero how
     * often it is asked.
     *
     * @param  \SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect  $effect
     * @return void
     */
    private function bindDeadline(DeadlineEffect $effect): void
    {
        $this->deadlineAsked = 0;

        $answer = function () use ($effect): DeadlineEffect {
            $this->deadlineAsked++;

            return $effect;
        };

        $this->app?->instance(ProviderSessionDeadline::class, new readonly class ($answer) implements ProviderSessionDeadline {
            /**
             * Constructor.
             *
             * @param  \Closure(): \SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect  $answer
             */
            public function __construct(

                /** What every question is answered. */
                private \Closure $answer,
            ) {}

            /**
             * The effect given.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect
             */
            #[\Override]
            public function effect(VerifiedResult $result): DeadlineEffect
            {
                unset($result);

                return ($this->answer)();
            }
        });
    }

    /**
     * A linking contract that resolves every result to the identity given.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Contracts\Linker
     */
    private static function linker(?IdentityReference $identity): Linker
    {
        return new readonly class ($identity) implements Linker {
            /**
             * Constructor.
             *
             * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             */
            public function __construct(

                /** What every result resolves to. */
                private ?IdentityReference $identity,
            ) {}

            /**
             * The identity given.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return ?\SineMacula\Laravel\Sso\Identities\IdentityReference
             */
            #[\Override]
            public function resolve(VerifiedResult $result): ?IdentityReference
            {
                unset($result);

                return $this->identity;
            }
        };
    }

    /**
     * A public reference of its own, so a test may store several requests.
     *
     * @return string
     */
    private function nextReference(): string
    {
        $this->references++;

        return sprintf('Nq8tVv3w0kLmNoPqRsTuVwXyZ01%05d', $this->references);
    }

    /**
     * The registered application of the name.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Applications\Application
     *
     * @throws \LogicException
     */
    private static function application(string $name): Application
    {
        return app(ApplicationRegistry::class)->find($name) ?? throw new \LogicException("No [{$name}] application is registered.");
    }

    /**
     * The shipped migration of the single-use keys.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function singleUseMigration(): Migration
    {
        return require dirname(__DIR__, 4) . self::SINGLE_USE_MIGRATION;
    }
}
