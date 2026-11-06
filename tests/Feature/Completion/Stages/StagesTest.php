<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion\Stages;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\ApplicationRegistry;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\ResultBuilder;
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
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Contracts\ReinitiatingDriver;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Links\ExampleLinks;
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
#[CoversClass(RecordReplay::class)]
#[CoversClass(ResolveLink::class)]
#[CoversClass(CheckEnforcement::class)]
#[CoversClass(CheckPurpose::class)]
#[CoversClass(DecideUnlinked::class)]
#[CoversClass(IssueHandoff::class)]
final class StagesTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

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

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'protocol'          => VerifyingDriver::NAME,
            'enabled'           => true,
            'settings'          => ['issuer' => VerifyingDriver::ISSUER],
            'attribute_mapping' => ['email' => 'mail'],
        ]);
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
     * Correlation refuses an unsolicited response at a driver that does not
     * re-initiate, and an uncorrelated one, with `request_unknown`, from the
     * state the response arrived in, with no trusted redirect target.
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
     * Correlation hands an unsolicited response at a driver that re-initiates
     * to re-initiation, with the driver's correlation and the rest of the state
     * kept: neither going on nor refused, with no reason and no trusted
     * redirect target.
     *
     * @return void
     */
    public function testCorrelationHandsAnUnsolicitedResponseToReinitiation(): void
    {
        $correlation = Correlation::unsolicited();
        $state       = $this->arrivedThroughAReinitiatingDriver($correlation);
        $outcome     = $this->stage(CorrelateResponse::class)->run($state);

        self::assertSame([true, false, false, null], [$outcome->isReinitiating(), $outcome->isProceeding(), $outcome->isRefused(), $outcome->reason]);
        self::assertSame($correlation, $outcome->state->correlation);
        self::assertSame($state->connection, $outcome->state->connection);
        self::assertSame($state->request, $outcome->state->request);
        self::assertFalse($outcome->state->hasRedirectTarget());
    }

    /**
     * At a driver that re-initiates, a solicited response still goes on and an
     * uncorrelated one is still refused with `request_unknown`; neither is
     * handed to re-initiation.
     *
     * @return void
     */
    public function testAReinitiatingDriverReinitiatesOnlyAnUnsolicitedResponse(): void
    {
        $state        = $this->arrivedThroughAReinitiatingDriver(Correlation::solicited(self::STATE), Correlation::uncorrelated());
        $solicited    = $this->stage(CorrelateResponse::class)->run($state);
        $uncorrelated = $this->stage(CorrelateResponse::class)->run($state);

        self::assertSame([true, false, null], [$solicited->isProceeding(), $solicited->isReinitiating(), $solicited->reason]);
        self::assertSame([false, false, FailureReason::REQUEST_UNKNOWN], [$uncorrelated->isProceeding(), $uncorrelated->isReinitiating(), $uncorrelated->reason]);
        self::assertNull($uncorrelated->state->correlation);
    }

    /**
     * Each outcome is exactly one of going on, refused and handed to
     * re-initiation.
     *
     * @return void
     */
    public function testAnOutcomeIsExactlyOneOfItsKinds(): void
    {
        $state = $this->arrived();

        $kinds = static fn (StageOutcome $outcome): array => [$outcome->isProceeding(), $outcome->isRefused(), $outcome->isReinitiating(), $outcome->reason];

        self::assertSame([true, false, false, null], $kinds(StageOutcome::proceed($state)));
        self::assertSame([false, true, false, FailureReason::REPLAYED], $kinds(StageOutcome::refuse($state, FailureReason::REPLAYED)));
        self::assertSame([false, false, true, null], $kinds(StageOutcome::reinitiate($state)));
        self::assertSame($state, StageOutcome::reinitiate($state)->state);
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
     * Validation goes on with the replay record the driver asked for, and with
     * none when it asked for none.
     *
     * @return void
     */
    public function testValidationKeepsTheReplayRecordTheDriverAskedFor(): void
    {
        $state = $this->consumed();

        self::assertNull($this->stage(ValidateResponse::class)->run($state)->state->replay);

        $this->driver->replay = ReplayRecord::samlAssertion($this->connection->id, VerifyingDriver::ISSUER, '_assertion-1', $this->clock->now()->addMinutes(5));

        self::assertSame($this->driver->replay, $this->stage(ValidateResponse::class)->run($state)->state->replay);
    }

    /**
     * The replay recording goes on when there is nothing to record, records a
     * record once and refuses it again with `replayed`, and refuses a record no
     * longer acceptable with `assertion_expired`, recording nothing.
     *
     * @return void
     */
    public function testTheReplayRecordingRecordsOnce(): void
    {
        $state  = $this->consumed();
        $record = ReplayRecord::samlAssertion($this->connection->id, VerifyingDriver::ISSUER, '_assertion-1', $this->clock->now()->addSecond());

        self::assertSame($state, $this->stage(RecordReplay::class)->run($state)->state);
        self::assertTrue($this->stage(RecordReplay::class)->run($state)->isProceeding());
        self::assertSame(0, self::recordedKeys());

        $first  = $this->stage(RecordReplay::class)->run($state->withReplay($record));
        $second = $this->stage(RecordReplay::class)->run($state->withReplay($record));

        self::assertTrue($first->isProceeding());
        self::assertSame(FailureReason::REPLAYED, $second->reason);
        self::assertSame(1, self::recordedKeys());
        self::assertSame(ReplayRecord::SAML_ASSERTION, SingleUseKey::query()->sole()->namespace);

        $atNow = ReplayRecord::samlAssertion($this->connection->id, VerifyingDriver::ISSUER, '_assertion-2', $this->clock->now());
        $past  = ReplayRecord::samlAssertion($this->connection->id, VerifyingDriver::ISSUER, '_assertion-3', $this->clock->now()->subSecond());

        self::assertSame(FailureReason::ASSERTION_EXPIRED, $this->stage(RecordReplay::class)->run($state->withReplay($atNow))->reason);
        self::assertSame(FailureReason::ASSERTION_EXPIRED, $this->stage(RecordReplay::class)->run($state->withReplay($past))->reason);
        self::assertSame(1, self::recordedKeys());
    }

    /**
     * A record is scoped by connection and issuer: the same assertion id from
     * another issuer or through another connection is recorded on its own.
     *
     * @return void
     */
    public function testTheReplayRecordingIsScopedByConnectionAndIssuer(): void
    {
        $state = $this->consumed();
        $until = $this->clock->now()->addMinutes(5);

        $scopes = [[$this->connection->id, VerifyingDriver::ISSUER], [$this->connection->id, 'https://other.example.com'], ['01jbanotherconnection00000', VerifyingDriver::ISSUER]];

        foreach ($scopes as [$connection, $issuer]) {
            $record = ReplayRecord::samlAssertion($connection, $issuer, '_assertion-1', $until);

            self::assertTrue($this->stage(RecordReplay::class)->run($state->withReplay($record))->isProceeding());
        }

        self::assertSame(3, self::recordedKeys());
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
        self::assertTrue($linked->state->resolution?->isLinked());
        self::assertSame('link-' . $identity->id, $linked->state->resolution->linkId);
        self::assertTrue($unlinked->isProceeding());
        self::assertNull($unlinked->state->linkedIdentity);
        self::assertTrue($unlinked->state->resolution?->isAbsent());
    }

    /**
     * Enforcement refuses a required policy the connection does not satisfy,
     * and goes on with the state unchanged under one it satisfies, or one that
     * requires nothing; asked for the connection's tenant and the application.
     *
     * @return void
     */
    public function testEnforcementRefusesAnUnsatisfiedPolicyAndKeepsTheState(): void
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
        self::assertSame(array_fill(0, 4, $state), array_map(static fn (StageOutcome $outcome): CompletionState => $outcome->state, $outcomes));
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
        $state = $linked ? $state->withResolution(ExampleLinks::resolution(new IdentityReference('App\Models\User', '42'))) : $state;

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
        $state  = $this->verified(Purpose::REAUTHENTICATE, 'native')->withResolution(ExampleLinks::resolution($linked));

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
     * A verified state with no resolved link: linking by a verified domain
     * finds nothing to reserve, and provisioning nothing to stop, so each
     * passes it on unchanged.
     *
     * @return void
     */
    public function testAStateWithNoResolvedLinkPassesThrough(): void
    {
        $state = $this->verified();

        foreach ([DomainReservation::class, Provisioning::class] as $class) {

            $outcome = $this->stage($class)->run($state);

            self::assertTrue($outcome->isProceeding());
            self::assertSame($state, $outcome->state);
        }
    }

    /**
     * Rows of `[purpose, the link as it resolved, the reason it refuses]`: each
     * purpose reaches its own rules, and a refusal keeps their exact reason.
     *
     * @return iterable<string, array{
     *     0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose,
     *     1: \SineMacula\Laravel\Sso\Links\LinkResolution,
     *     2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     * }>
     */
    public static function providePurposes(): iterable
    {
        $person  = new IdentityReference('App\Models\User', '7');
        $another = new IdentityReference('App\Models\User', '8');

        yield 'a sign-in of a linked result' => [Purpose::SIGN_IN, LinkResolution::linked($person, 'link-7'), null];
        yield 'a sign-in of a suspended link' => [Purpose::SIGN_IN, LinkResolution::suspended($person, 'link-7'), FailureReason::LINK_SUSPENDED];
        yield 'a sign-in of a reserved link' => [Purpose::SIGN_IN, LinkResolution::reserved(), FailureReason::LINK_RESERVED];
        yield 'a sign-in of a link of unknown scope' => [Purpose::SIGN_IN, LinkResolution::scopeUnknown($person, 'link-7'), FailureReason::PRINCIPAL_SCOPE_UNKNOWN];
        yield 'a link of an absent subject' => [Purpose::LINK, LinkResolution::absent(), null];
        yield 'a link of a reserved subject' => [Purpose::LINK, LinkResolution::reserved(), FailureReason::LINK_RESERVED];
        yield 'a link of another identity\'s subject' => [Purpose::LINK, LinkResolution::linked($another, 'link-8'), FailureReason::SUBJECT_ALREADY_LINKED];
        yield 'a link of its own link of unknown scope' => [Purpose::LINK, LinkResolution::scopeUnknown($person, 'link-7'), FailureReason::PRINCIPAL_SCOPE_UNKNOWN];
        yield 'a link of another identity\'s link of unknown scope' => [Purpose::LINK, LinkResolution::scopeUnknown($another, 'link-8'), FailureReason::SUBJECT_ALREADY_LINKED];
        yield 'a reauthentication of a suspended link' => [Purpose::REAUTHENTICATE, LinkResolution::suspended($person, 'link-7'), FailureReason::LINK_SUSPENDED];
        yield 'a reauthentication of another identity' => [Purpose::REAUTHENTICATE, LinkResolution::linked($another, 'link-8'), FailureReason::IDENTITY_MISMATCH];
        yield 'a reauthentication of a link of unknown scope' => [Purpose::REAUTHENTICATE, LinkResolution::scopeUnknown($person, 'link-7'), FailureReason::PRINCIPAL_SCOPE_UNKNOWN];
    }

    /**
     * The stage asks the rules of the flow's purpose, and no other: it goes on
     * with the state exactly as it was, or refuses for the reason they gave.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $resolution
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('providePurposes')]
    public function testThePurposesRulesDecide(Purpose $purpose, LinkResolution $resolution, ?FailureReason $reason): void
    {
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Linker::class, app(LinkStore::class));

        $state   = $this->verified($purpose)->withResolution($resolution);
        $outcome = $this->stage(CheckPurpose::class)->run($state);

        self::assertSame($reason, $outcome->reason);
        self::assertSame($reason === null, $outcome->isProceeding());
        self::assertSame($state, $outcome->state);
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
        yield 'purpose rules' => [CheckPurpose::class, 'A purpose\'s rules are checked once the request is consumed.'];
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
     * The state of a post that arrived at a connection whose driver
     * re-initiates, and correlates the responses it is asked about as given, in
     * order.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  ...$next
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private function arrivedThroughAReinitiatingDriver(Correlation $correlation, Correlation ...$next): CompletionState
    {
        $driver = self::createStubForIntersectionOfInterfaces([ProtocolDriver::class, ReinitiatingDriver::class]);

        $driver->method('correlate')->willReturn($correlation, ...array_values($next));

        app(ProtocolManager::class)->extend('reinitiating', fn (): ProtocolDriver => $driver);

        $connection = $this->makeConnection(['protocol' => 'reinitiating', 'enabled' => true]);

        return CompletionState::arrived($connection->id, new CompletionRequest('POST', '', ['SAMLResponse' => 'unread']))->withConnection($connection);
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
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result): LinkResolution
            {
                unset($result);

                return ExampleLinks::resolution($this->identity);
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
     * How many keys the single-use store holds now.
     *
     * @return int
     *
     * @phpstan-impure
     */
    private static function recordedKeys(): int
    {
        return SingleUseKey::query()->count();
    }
}
