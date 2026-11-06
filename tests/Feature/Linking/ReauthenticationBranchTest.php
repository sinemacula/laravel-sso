<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Applications\ApplicationGate;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\Rules\ReauthenticationRules;
use SineMacula\Laravel\Sso\Completion\Stages\CheckPurpose;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\ReauthenticationBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Attacks a `reauthenticate` through its public paths (SSO-5.10, SSO-9.5,
 * SSO-9.9, `docs/design/linking.md`): it accepts only the exact link that
 * established the session, compared by id; the identity, the session, the
 * application and the connection must all match, with the session's row locked
 * through the write; what is renewed is the authentication time and evidence
 * newly accepted, and nothing else; and it never acknowledges a sign-in,
 * activates a reservation or creates a link.
 *
 * Two session contracts stand in for the application's. `RecordingSessions`
 * records the renewal it is asked for; the second, built here over a table on
 * the storage connection, compares every value as an implementation must,
 * records every call, and lets a rollback undo the renewal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckPurpose::class)]
#[CoversClass(ReauthenticationBranch::class)]
#[CoversClass(ReauthenticationRules::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(AuthorizationRequestService::class)]
final class ReauthenticationBranchTest extends LinkingTestCase
{
    /** @var string The session the flows are started on. */
    private const string SESSION = 'session-1';

    /** @var string The table the second session contract keeps its sessions in. */
    private const string SESSIONS = 'reauthentication_test_sessions';

    /** @var string The authentication time every session holds until renewed. */
    private const string EARLIER = '2026-11-01T08:00:00.000000Z';

    /** @var string How an instant is compared. */
    private const string INSTANT = 'Y-m-d\TH:i:s.u\Z';

    /** @var string What an unbound `admit()` throws. */
    private const string NO_TRANSACTION = 'A session is admitted inside the caller\'s transaction on the package\'s storage connection (decision D5).';

    /** @var string What the standalone path throws. */
    private const string STANDALONE = 'A [sign_in] or [reauthenticate] code is redeemed through admit(), in the caller\'s transaction (decision D5).';

    /** @var object{calls: list<array<int, mixed>>, failing: ?string, failure: ?\Throwable}&\SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions The contract over the table, once a test binds it. */
    private ReauthenticationSessions $table; // @phpstan-ignore property.uninitialized

    /**
     * Bind a fresh caller, and create the second contract's table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        DB::connection(StorageConnection::name())->getSchemaBuilder()->create(self::SESSIONS, static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('identity_type');
            $table->string('identity_id');
            $table->string('application');
            $table->string('connection_id');
            $table->string('link_id')->nullable();
            $table->boolean('active');
            $table->string('authenticated_at');
            $table->string('expires_at');
            $table->string('refresh_token');
            $table->string('provenance');
            $table->string('evidence')->nullable();
        });
    }

    /**
     * Drop the second contract's table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::connection(StorageConnection::name())->getSchemaBuilder()->dropIfExists(self::SESSIONS);

        parent::tearDown();
    }

    /**
     * A reauthentication through the session's own link renews the session with
     * the provider's time and no evidence, answers the identity, the session
     * and the link, and is admitted; the code is spent.
     *
     * @return void
     */
    public function testTheExactLinkRenewsTheProvidersTime(): void
    {
        $link     = $this->hold($this->person);
        $sessions = $this->recording($link);
        $at       = $this->clock->now()->subSeconds(30);

        $this->verifying->claims = $this->claimsAt($at);

        [$start, $completion] = $this->flow();

        $answer = $this->admit($completion, $start, Purpose::REAUTHENTICATE);

        self::assertTrue($answer->isAdmitted());
        self::assertSame(
            [$this->person->jsonSerialize(), $this->person->jsonSerialize(), self::SESSION, $link->id, null],
            [$answer->linkedIdentity?->jsonSerialize(), $answer->identity?->jsonSerialize(), $answer->sessionId, $answer->linkId, $answer->evidence],
        );
        self::assertSame(1, $sessions->renewals());
        self::assertSame(
            [self::SESSION, $at->format(self::INSTANT), null],
            [$sessions->renewed[0][0], $sessions->renewed[0][1]->utc()->format(self::INSTANT), $sessions->renewed[0][2]],
        );
        self::assertNotNull($this->storedCode($start)->redeemed_at);
    }

    /**
     * The start asks `standing()` alone, outside any transaction; redemption
     * asks `lockedStanding()` with exactly the identity, the session, the
     * application, the connection and the link, then renews, each inside the
     * caller's transaction and the redemption's savepoint.
     *
     * @return void
     */
    public function testTheContractIsAskedForExactlyTheFiveValues(): void
    {
        $link = $this->hold($this->person);

        $this->tableSession(self::SESSION, $link->id);

        $at                      = $this->clock->now()->subSeconds(5);
        $this->verifying->claims = $this->claimsAt($at);

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        self::assertSame([['standing', 0, $this->person->type, $this->person->id, self::SESSION, $this->connection->id]], $this->table->calls);

        $completion = $this->complete();

        self::assertCount(1, $this->table->calls);
        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isAdmitted());

        self::assertSame([
            ['standing', 0, $this->person->type, $this->person->id, self::SESSION, $this->connection->id],
            ['lockedStanding', 2, $this->person->type, $this->person->id, self::SESSION, 'web', $this->connection->id, $link->id],
            ['renewAuthentication', 2, $this->person->type, $this->person->id, self::SESSION, $at->format(self::INSTANT), null],
        ], $this->table->calls);
    }

    /**
     * Only the authentication time changes: the lifetime, the refresh token,
     * the sign-in provenance, the binding and earlier evidence are as they
     * were.
     *
     * @return void
     */
    public function testNothingButTheAuthenticationTimeIsTouched(): void
    {
        $link = $this->hold($this->person);

        $this->tableSession(self::SESSION, $link->id);

        $before = $this->sessionRow(self::SESSION);

        $at                      = $this->clock->now()->subSeconds(5);
        $this->verifying->claims = $this->claimsAt($at);

        [$start, $completion] = $this->flow();

        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isAdmitted());

        self::assertSame(array_replace($before, ['authenticated_at' => $at->format(self::INSTANT)]), $this->sessionRow(self::SESSION));
        self::assertSame('earlier-evidence', $this->sessionRow(self::SESSION)['evidence']);
    }

    /**
     * Evidence newly accepted is asked of the policy at redemption, for the
     * result and the locked connection at the clock's now, and handed to the
     * renewal and on the answer; earlier evidence is not asked about.
     *
     * @return void
     */
    public function testEvidenceAcceptedAtRedemptionIsPassedToTheRenewal(): void
    {
        $link     = $this->hold($this->person);
        $sessions = $this->recording($link);
        $accepted = new AcceptedEvidence($this->connection->id, $this->clock->now(), ['pwd'], 'class');
        $policy   = $this->policy($accepted);

        [$start, $completion] = $this->flow();

        self::assertSame([], $policy->asked, 'Evidence is asked at redemption, never at completion.');

        $this->clock->advance(5);

        $answer = $this->admit($completion, $start, Purpose::REAUTHENTICATE);

        self::assertSame($accepted, $answer->evidence);
        self::assertSame($accepted, $sessions->renewed[0][2]);
        self::assertSame(
            [[$start->reference?->value, $this->connection->id, $this->clock->now()->format(self::INSTANT)]],
            $policy->asked,
        );
    }

    /**
     * Evidence the policy finds insufficient renews the time all the same, with
     * `null`, and leaves what the session holds as it is.
     *
     * @return void
     */
    public function testInsufficientEvidenceIsNullAndLeavesEarlierEvidence(): void
    {
        $link   = $this->hold($this->person);
        $policy = $this->policy(null);

        $this->tableSession(self::SESSION, $link->id);

        [$start, $completion] = $this->flow();

        $answer = $this->admit($completion, $start, Purpose::REAUTHENTICATE);

        self::assertTrue($answer->isAdmitted());
        self::assertNull($answer->evidence);
        self::assertCount(1, $policy->asked);
        self::assertNull($this->table->calls[2][6]);
        self::assertSame('earlier-evidence', $this->sessionRow(self::SESSION)['evidence']);
    }

    /**
     * New evidence is added alongside what the session holds; it never stands
     * for a refresh of what it held.
     *
     * @return void
     */
    public function testNewEvidenceIsStoredWithTheRenewal(): void
    {
        $link = $this->hold($this->person);

        $this->policy(new AcceptedEvidence($this->connection->id, $this->clock->now(), ['pwd']));
        $this->tableSession(self::SESSION, $link->id);

        [$start, $completion] = $this->flow();

        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isAdmitted());
        self::assertSame('earlier-evidence,' . $this->connection->id, $this->sessionRow(self::SESSION)['evidence']);
    }

    /**
     * Evidence is never asked for a redemption refused before the write.
     *
     * @return void
     */
    public function testARefusalAsksNoEvidence(): void
    {
        $link     = $this->hold($this->person);
        $sessions = $this->recording($link);
        $policy   = $this->policy(new AcceptedEvidence($this->connection->id, $this->clock->now()));

        [$start, $completion] = $this->flow();

        $sessions->standing = SessionStanding::NOT_SIGNED_IN;

        $this->assertRefused(FailureReason::SESSION_INELIGIBLE, $this->admit($completion, $start, Purpose::REAUTHENTICATE), $start);
        self::assertSame([], $policy->asked);
    }

    /**
     * With the default contract nobody is signed in, so no flow starts, and no
     * request is stored; the refusal is one failure of the start.
     *
     * @return void
     */
    public function testTheDefaultContractStartsNothing(): void
    {
        self::assertInstanceOf(NoReauthenticationSessions::class, app(ReauthenticationSessions::class));

        $start = app(AuthorizationRequestService::class)->start('web', Purpose::REAUTHENTICATE, $this->connection->id, Clients::browser(), null, $this->person, self::SESSION);

        self::assertSame(FailureReason::SESSION_INELIGIBLE, $start->reason);
        self::assertSame(0, AuthorizationRequest::query()->count());
        $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::SESSION_INELIGIBLE);
    }

    /**
     * Rows of `[column, value]`: a session the start must not accept.
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideSessionsAtTheStart(): iterable
    {
        yield 'revoked' => ['active', false];
        yield 'of another identity' => ['identity_id', '8'];
        yield 'of another type of identity' => ['identity_type', 'App\Models\Admin'];
        yield 'of another connection' => ['connection_id', 'another-connection'];
    }

    /**
     * The start refuses a session its contract does not answer `signed_in` for.
     *
     * @param  string  $column
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideSessionsAtTheStart')]
    public function testTheStartRefusesASessionItsContractDoesNotAccept(string $column, mixed $value): void
    {
        $link = $this->hold($this->person);

        $this->tableSession(self::SESSION, $link->id, [$column => $value]);
        $this->startRecordingEvents();

        $start = app(AuthorizationRequestService::class)->start('web', Purpose::REAUTHENTICATE, $this->connection->id, Clients::browser(), null, $this->person, self::SESSION);

        self::assertSame(FailureReason::SESSION_INELIGIBLE, $start->reason);
        self::assertSame(0, AuthorizationRequest::query()->count());
        $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::SESSION_INELIGIBLE);
    }

    /**
     * A second subject linked to the same identity, where the limit allows two,
     * completes as the identity's; redemption refuses it as not the session's
     * bound link, and the session's own subject then renews it.
     *
     * @return void
     */
    public function testASecondLinkOfTheIdentityIsNotTheSessionsBoundLink(): void
    {
        $this->app?->instance(LinkLimit::class, new readonly class implements LinkLimit {
            /**
             * Allow two.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return int
             */
            #[\Override]
            public function maxLinks(IdentityReference $identity, SsoConnection $connection): int
            {
                unset($identity, $connection);

                return 2;
            }
        });

        $link     = $this->hold($this->person);
        $second   = $this->hold($this->person, subject: 'Subject-2');
        $sessions = $this->recording($link);

        self::assertNotSame($link->id, $second->id);

        $this->verifying->claims = $this->claimsAt($this->clock->now(), 'Subject-2');

        [$start, $completion] = $this->flow();

        self::assertSame($second->id, $this->storedCode($start)->link_id);

        $this->assertRefused(FailureReason::SESSION_INELIGIBLE, $this->admit($completion, $start, Purpose::REAUTHENTICATE), $start);
        self::assertSame(0, $sessions->renewals());

        $this->verifying->claims = $this->claims();

        [$start, $completion] = $this->flow();

        $answer = $this->admit($completion, $start, Purpose::REAUTHENTICATE);

        self::assertSame($link->id, $answer->linkId);
        self::assertSame(1, $sessions->renewals());
    }

    /**
     * Each way round.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideBooleans(): iterable
    {
        yield 'the session still bound to the old link' => [false];
        yield 'the session bound to the new one' => [true];
    }

    /**
     * A link deleted and made again for the same identity between completion
     * and redemption is another link: `identity_mismatch`, compared by id, even
     * when the session has since been bound to the new link.
     *
     * @param  bool  $rebound
     * @return void
     */
    #[DataProvider('provideBooleans')]
    public function testALinkDeletedAndRemadeIsAnotherLink(bool $rebound): void
    {
        $link     = $this->hold($this->person);
        $sessions = $this->recording($link);

        [$start, $completion] = $this->flow();

        self::assertTrue(app(LinkService::class)->remove($this->person, $link->id, Clients::browser())->isRemoved());

        $remade = $this->hold($this->person);

        self::assertNotSame($link->id, $remade->id);

        $sessions->boundLink = $rebound ? $remade->id : $link->id;

        $this->assertRefused(FailureReason::IDENTITY_MISMATCH, $this->admit($completion, $start, Purpose::REAUTHENTICATE), $start);
        self::assertSame(0, $sessions->renewals());
    }

    /**
     * A link suspended at completion is `link_suspended` with no code, and a
     * latched suspension stays so with the scope back within the tenant.
     *
     * @return void
     */
    public function testALinkSuspendedAtCompletionIsRefused(): void
    {
        $link     = $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);
        $sessions = $this->recording($link);

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        $first = $this->complete();

        self::assertSame(FailureReason::LINK_SUSPENDED, $first->reason);
        self::assertNull($first->handoff);
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);

        $this->scope->verdict = ScopeVerdict::WITHIN_TENANT;

        $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);
        self::assertSame(0, $sessions->renewals());
        self::assertSame(0, StoredCode::query()->count());
    }

    /**
     * Each way a link comes to be suspended.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideSuspensions(): iterable
    {
        yield 'found by the resolution' => [false];
        yield 'by the principal change' => [true];
    }

    /**
     * A link suspended between completion and redemption is `link_suspended`,
     * by a resolution finding the scope widened or by the principal change
     * itself, with no renewal and the session never asked about.
     *
     * @param  bool  $byWidening
     * @return void
     */
    #[DataProvider('provideSuspensions')]
    public function testALinkSuspendedAtRedemptionIsRefused(bool $byWidening): void
    {
        $link = $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        $this->tableSession(self::SESSION, $link->id);

        [$start, $completion] = $this->flow();

        if ($byWidening) {
            DB::connection(StorageConnection::name())->transaction(fn (): int => app(ScopeWidening::class)->widened($this->person, 'tenant-2', Clients::browser()));
        } else {
            $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;
        }

        $answer = $this->admit($completion, $start, Purpose::REAUTHENTICATE);

        self::assertSame(FailureReason::LINK_SUSPENDED, $answer->reason);
        self::assertNotNull($this->storedCode($start)->redeemed_at);
        self::assertSame(self::EARLIER, $this->sessionRow(self::SESSION)['authenticated_at']);
        self::assertSame(['standing'], array_column($this->table->calls, 0));
    }

    /**
     * A result resolving to another identity, or to nothing, is refused at
     * completion, `identity_mismatch`, with no code, whatever the application
     * allows of an unlinked handoff.
     *
     * @return void
     */
    public function testAResultOfAnotherIdentityOrNoneIsRefusedAtCompletion(): void
    {
        $sessions = new RecordingSessions('link');

        $this->app?->instance(ReauthenticationSessions::class, $sessions);

        config()->set('sso.applications.web.unlinked_handoffs', true);

        $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        $nothing = $this->complete();

        self::assertSame([true, FailureReason::IDENTITY_MISMATCH, null], [$nothing->isFailed(), $nothing->reason, $nothing->handoff]);

        $this->hold(new IdentityReference('App\Models\User', '8'));
        $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        $another = $this->complete();

        self::assertSame([true, FailureReason::IDENTITY_MISMATCH, null], [$another->isFailed(), $another->reason, $another->handoff]);
        self::assertSame(0, StoredCode::query()->count());
    }

    /**
     * What a link comes to.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideGoneLinks(): iterable
    {
        yield 'nothing' => [false];
        yield 'another identity' => [true];
    }

    /**
     * A result that comes to resolve to nothing, or to another identity, after
     * its completion is refused at redemption.
     *
     * @param  bool  $another
     * @return void
     */
    #[DataProvider('provideGoneLinks')]
    public function testALinkGoneAtRedemptionIsRefused(bool $another): void
    {
        $link     = $this->hold($this->person);
        $sessions = $this->recording($link);

        [$start, $completion] = $this->flow();

        self::assertTrue(app(LinkService::class)->remove($this->person, $link->id, Clients::browser())->isRemoved());

        if ($another) {
            $this->hold(new IdentityReference('App\Models\User', '8'));
        }

        $this->assertRefused(FailureReason::IDENTITY_MISMATCH, $this->admit($completion, $start, Purpose::REAUTHENTICATE), $start);
        self::assertSame(0, $sessions->renewals());
    }

    /**
     * Rows of what happens to the session between completion and redemption:
     * the columns changed, or `null` for gone.
     *
     * @return iterable<string, array{0: ?array<string, mixed>}>
     */
    public static function provideSessionChanges(): iterable
    {
        yield 'logged out' => [null];
        yield 'revoked' => [['active' => false]];
        yield 'rebound to another link' => [['link_id' => 'another-link']];
        yield 'with no bound link' => [['link_id' => null]];
        yield 'of another application' => [['application' => 'mobile']];
        yield 'of another connection' => [['connection_id' => 'another-connection']];
        yield 'of another identity' => [['identity_id' => '8']];
        yield 'of another type of identity' => [['identity_type' => 'App\Models\Admin']];
    }

    /**
     * A session that is no longer active, of the application and the
     * connection, and bound to exactly the link is `session_ineligible`: the
     * code stays spent, and nothing is renewed.
     *
     * @param  ?array<string, mixed>  $change
     * @return void
     */
    #[DataProvider('provideSessionChanges')]
    public function testASessionChangedSinceCompletionIsRefused(?array $change): void
    {
        $link = $this->hold($this->person);

        $this->tableSession(self::SESSION, $link->id);

        [$start, $completion] = $this->flow();

        if ($change === null) {
            $this->sessions()->where('id', self::SESSION)->delete();
        } else {
            $this->sessions()->where('id', self::SESSION)->update($change);
        }

        $this->startRecordingEvents();

        $answer = $this->admit($completion, $start, Purpose::REAUTHENTICATE);

        self::assertSame(FailureReason::SESSION_INELIGIBLE, $answer->reason);
        self::assertNotNull($this->storedCode($start)->redeemed_at);
        self::assertSame(['standing', 'lockedStanding'], array_column($this->table->calls, 0));
        $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::SESSION_INELIGIBLE);
    }

    /**
     * A code renews the session it was started on and no other, and names it,
     * so the redeemer can tell it from its own; a code for a session gone never
     * falls back on another of the identity's.
     *
     * @return void
     */
    public function testACodeForAnotherSessionRenewsOnlyThatSession(): void
    {
        $link = $this->hold($this->person);

        $this->tableSession(self::SESSION, $link->id);
        $this->tableSession('session-2', $link->id);

        [$start, $completion] = $this->flow();

        $answer = $this->admit($completion, $start, Purpose::REAUTHENTICATE);

        self::assertSame(self::SESSION, $answer->sessionId);
        self::assertNotSame(self::EARLIER, $this->sessionRow(self::SESSION)['authenticated_at']);
        self::assertSame(self::EARLIER, $this->sessionRow('session-2')['authenticated_at']);

        [$start, $completion] = $this->flow();

        $this->sessions()->where('id', self::SESSION)->delete();

        self::assertSame(FailureReason::SESSION_INELIGIBLE, $this->admit($completion, $start, Purpose::REAUTHENTICATE)->reason);
        self::assertSame(self::EARLIER, $this->sessionRow('session-2')['authenticated_at']);
    }

    /**
     * Verifiers of the wrong client.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideWrongVerifiers(): iterable
    {
        yield 'too short' => ['short'];
        yield 'another of the right shape' => [str_repeat('v', 43)];
    }

    /**
     * A verifier that does not satisfy the code's challenge, malformed or
     * another client's, refuses it and spends it, renewing nothing.
     *
     * @param  string  $verifier
     * @return void
     */
    #[DataProvider('provideWrongVerifiers')]
    public function testAVerifierMismatchRenewsNothing(string $verifier): void
    {
        $sessions = $this->recording($this->hold($this->person));

        [$start, $completion] = $this->flow();

        $answer = $this->admitWith($completion, Purpose::REAUTHENTICATE, 'web', $this->connection->id, $verifier);

        $this->assertRefused(FailureReason::VERIFIER_MISMATCH, $answer, $start);
        self::assertSame(0, $sessions->renewals());
    }

    /**
     * Rows of what the redeemer's endpoint asks for that the code is not.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: string, 2: ?string, 3: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideWrongEndpoints(): iterable
    {
        yield 'the sign-in endpoint' => [Purpose::SIGN_IN, 'web', null, FailureReason::PURPOSE_MISMATCH];
        yield 'the link endpoint' => [Purpose::LINK, 'web', null, FailureReason::PURPOSE_MISMATCH];
        yield 'another application' => [Purpose::REAUTHENTICATE, 'mobile', null, FailureReason::APPLICATION_MISMATCH];
        yield 'another connection' => [Purpose::REAUTHENTICATE, 'web', 'another-connection', FailureReason::CONNECTION_MISMATCH];
    }

    /**
     * A code redeemed by anything but the operation of its purpose, for its
     * application and its connection, renews nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  ?string  $connection
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideWrongEndpoints')]
    public function testAnotherEndpointRenewsNothing(Purpose $purpose, string $application, ?string $connection, FailureReason $reason): void
    {
        $sessions = $this->recording($this->hold($this->person));

        [$start, $completion] = $this->flow();

        $answer = $this->admitWith($completion, $purpose, $application, $connection ?? $this->connection->id, (string) $start->verifier?->reveal());

        $this->assertRefused($reason, $answer, $start);
        self::assertSame(0, $sessions->renewals());
    }

    /**
     * A code redeemed twice is `replayed`, and renews once.
     *
     * @return void
     */
    public function testAReplayRenewsNothingMore(): void
    {
        $sessions = $this->recording($this->hold($this->person));

        [$start, $completion] = $this->flow();

        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isAdmitted());

        self::assertSame(FailureReason::REPLAYED, $this->admit($completion, $start, Purpose::REAUTHENTICATE)->reason);
        self::assertSame(1, $sessions->renewals());
    }

    /**
     * A code past its expiry is `handoff_expired`, and renews nothing, however
     * fresh the authentication was.
     *
     * @return void
     */
    public function testAnExpiredCodeRenewsNothing(): void
    {
        $sessions = $this->recording($this->hold($this->person));

        [$start, $completion] = $this->flow();

        $this->clock->advance(301);

        $this->assertRefused(FailureReason::HANDOFF_EXPIRED, $this->admit($completion, $start, Purpose::REAUTHENTICATE), $start);
        self::assertSame(0, $sessions->renewals());
    }

    /**
     * The standalone `redeem()` refuses the code with an exception, renews
     * nothing and leaves it unconsumed, and `admit()` then redeems it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheStandaloneRedeemRefusesAndLeavesTheCodeUnconsumed(): void
    {
        $sessions = $this->recording($this->hold($this->person));

        [$start, $completion] = $this->flow();

        $code     = (string) $completion->handoff?->code->reveal();
        $verifier = (string) $start->verifier?->reveal();

        try {
            app(HandoffRedemption::class)->redeem(Purpose::REAUTHENTICATE, 'web', $this->connection->id, $code, $verifier, Clients::browser());
            self::fail('The standalone path redeemed a reauthentication.');
        } catch (\LogicException $exception) {
            self::assertSame(self::STANDALONE, $exception->getMessage());
        }

        self::assertNull($this->storedCode($start)->redeemed_at);
        self::assertSame(0, $sessions->renewals());

        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isAdmitted());
        self::assertSame(1, $sessions->renewals());
    }

    /**
     * `admit()` with no transaction open throws before the code is touched.
     *
     * @return void
     */
    public function testAdmitWithNoTransactionThrows(): void
    {
        $sessions = $this->recording($this->hold($this->person));

        [$start, $completion] = $this->flow();

        $code     = (string) $completion->handoff?->code->reveal();
        $verifier = (string) $start->verifier?->reveal();

        try {
            app(HandoffRedemption::class)->admit(Purpose::REAUTHENTICATE, 'web', $this->connection->id, $code, $verifier, Clients::browser());
            self::fail('A reauthentication was admitted with no transaction open.');
        } catch (\LogicException $exception) {
            self::assertSame(self::NO_TRANSACTION, $exception->getMessage());
        }

        self::assertNull($this->storedCode($start)->redeemed_at);
        self::assertSame(0, $sessions->renewals());
    }

    /**
     * The caller's rollback takes the renewal, the consumption and the events
     * with it; a retry of the whole transaction renews once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallersRollbackKeepsNothing(): void
    {
        $link = $this->hold($this->person);

        $this->tableSession(self::SESSION, $link->id);

        [$start, $completion] = $this->flow();

        $before = $this->sessionRow(self::SESSION);

        $this->startRecordingEvents();

        try {
            DB::connection(StorageConnection::name())->transaction(function () use ($start, $completion, $before): void {

                self::assertTrue($this->admitWith($completion, Purpose::REAUTHENTICATE, 'web', $this->connection->id, (string) $start->verifier?->reveal())->isAdmitted());
                self::assertNotSame($before, $this->sessionRow(self::SESSION));

                throw new \RuntimeException('The caller rolled back.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('The caller rolled back.', $exception->getMessage());
        }

        self::assertSame($before, $this->sessionRow(self::SESSION));
        self::assertNull($this->storedCode($start)->redeemed_at);
        $this->assertNoEvents();

        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isAdmitted());
        self::assertNotSame($before, $this->sessionRow(self::SESSION));
    }

    /**
     * Rows of `[call]`: the contract's call that fails.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideFailingCalls(): iterable
    {
        yield 'the renewal' => ['renewAuthentication'];
        yield 'the locked read' => ['lockedStanding'];
    }

    /**
     * An exception from the contract propagates as it is, rolls the redemption
     * back with the code unconsumed, and reports nothing; a retry succeeds.
     *
     * @param  string  $call
     * @return void
     */
    #[DataProvider('provideFailingCalls')]
    public function testTheContractsExceptionRollsTheRedemptionBack(string $call): void
    {
        $link = $this->hold($this->person);

        $this->tableSession(self::SESSION, $link->id);

        [$start, $completion] = $this->flow();

        $before  = $this->sessionRow(self::SESSION);
        $failure = new \RuntimeException('The session store failed.');

        $this->table->failing = $call;    // @phpstan-ignore assign.propertyReadOnly
        $this->table->failure = $failure; // @phpstan-ignore assign.propertyReadOnly

        $this->startRecordingEvents();

        try {
            $this->admit($completion, $start, Purpose::REAUTHENTICATE);
            self::fail('The contract\'s exception was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame($before, $this->sessionRow(self::SESSION));
        self::assertNull($this->storedCode($start)->redeemed_at);
        $this->assertNoEvents();

        $this->table->failure = null; // @phpstan-ignore assign.propertyReadOnly

        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isAdmitted());
    }

    /**
     * A `reauthenticate` never completes a sign-in on its connection.
     *
     * @return void
     */
    public function testItNeverAcknowledgesASignIn(): void
    {
        $this->recording($this->hold($this->person));

        [$start, $completion] = $this->flow();

        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isAdmitted());
        self::assertFalse(Connection::query()->whereKey($this->connection->id)->sole()->has_completed_sign_in);
    }

    /**
     * An unlinked subject, on a verified domain a sign-in would reserve a link
     * through, makes no link and no reservation.
     *
     * @return void
     */
    public function testAnUnlinkedSubjectNeverCreatesALinkOrReservation(): void
    {
        $this->app?->instance(ReauthenticationSessions::class, new RecordingSessions('link'));

        $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        self::assertSame(FailureReason::IDENTITY_MISMATCH, $this->complete()->reason);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A subject another flow's reservation holds is refused at completion and
     * the reservation is left as it was: never activated, never removed.
     *
     * @return void
     */
    public function testAReservationAtCompletionIsNeitherActivatedNorRemoved(): void
    {
        $sessions = new RecordingSessions('link');

        $this->app?->instance(ReauthenticationSessions::class, $sessions);

        $this->start();

        self::assertTrue($this->complete()->isCompleted());

        $reserved = Link::query()->sole();

        self::assertSame(LinkState::RESERVED, $reserved->state);

        $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        self::assertSame(FailureReason::IDENTITY_MISMATCH, $this->complete()->reason);

        $after = Link::query()->sole();

        self::assertSame([LinkState::RESERVED, $reserved->id, $reserved->reservation_id], [$after->state, $after->id, $after->reservation_id]);
        self::assertSame(0, $sessions->renewals());
    }

    /**
     * A link removed since completion and reserved by another flow is refused
     * at redemption, the reservation left as it was: a `reauthenticate` code
     * holds none to discard, and no link is activated for it.
     *
     * @return void
     */
    public function testAReservationAtRedemptionIsNeitherActivatedNorRemoved(): void
    {
        $link     = $this->hold($this->person);
        $sessions = $this->recording($link);

        [$start, $completion] = $this->flow();

        self::assertTrue(app(LinkService::class)->remove($this->person, $link->id, Clients::browser())->isRemoved());

        $this->start();

        self::assertTrue($this->complete()->isCompleted());

        $reserved = Link::query()->sole();

        self::assertSame(LinkState::RESERVED, $reserved->state);

        $this->assertRefused(FailureReason::IDENTITY_MISMATCH, $this->admit($completion, $start, Purpose::REAUTHENTICATE), $start);

        $after = Link::query()->sole();

        self::assertSame([LinkState::RESERVED, $reserved->reservation_id], [$after->state, $after->reservation_id]);
        self::assertSame(0, $sessions->renewals());
    }

    /**
     * A stored code whose result states no authentication time, which the
     * completion would never have issued, is a refusal and not an error: the
     * code stays spent, and the contract is not asked.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAStoredResultWithNoAuthenticationTimeIsRefused(): void
    {
        $link     = $this->hold($this->person);
        $sessions = $this->recording($link);
        $verifier = Verifier::generate();

        $grant = new HandoffGrant(
            result: $this->resultWithNoTime(),
            challenge: S256Challenge::of($verifier),
            expiresAt: $this->clock->now()->addMinute(),
            trustVersion: $this->connection->trust_version,
            linkedIdentity: $this->person,
            identity: $this->person,
            sessionId: self::SESSION,
            linkId: $link->id,
        );

        $code = app(DatabaseHandoffStore::class)->issue($grant)->code->reveal();

        $this->startRecordingEvents();

        $answer = $this->connection->getConnection()->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::REAUTHENTICATE, 'web', $this->connection->id, $code, $verifier->reveal(), Clients::browser()),
        );

        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, $answer->reason);
        self::assertSame(0, $sessions->renewals());
        $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::AUTHENTICATION_EXPIRED);
    }

    /**
     * An adapter redeeming its own code through the recheck is held to the same
     * rules: a result with no time is `authentication_expired` before the
     * session is asked about; a binding naming no identity, or no link, is
     * `identity_mismatch`; and a binding naming no session is that adapter's
     * mistake.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnAdapterIsHeldToTheSameRulesThroughTheRecheck(): void
    {
        $link = $this->hold($this->person);

        $this->tableSession(self::SESSION, $link->id);

        $good     = new HandoffBinding($this->person, $link->id, $this->person, self::SESSION, trustVersion: 0);
        $noTime   = $this->resultWithNoTime();
        $withTime = $this->resultWith(new AuthenticationContext($this->clock->now()));
        $bind     = static fn (?IdentityReference $linked, ?string $linkId, ?IdentityReference $identity, ?string $session): HandoffBinding => new HandoffBinding(
            $linked,
            $linkId,
            $identity,
            $session,
            trustVersion: 0,
        );

        DB::connection(StorageConnection::name())->transaction(function () use ($good, $noTime, $withTime, $link, $bind): void {

            $recheck = app(HandoffRecheck::class);
            $lock    = $recheck->lock('tenant-1', $this->connection->id, 'web');

            self::assertSame(RecheckOutcome::AUTHENTICATION_EXPIRED, $recheck->recheck($noTime, $good, $lock, Clients::browser()));
            self::assertSame(RecheckOutcome::AUTHENTICATION_EXPIRED, $recheck->admit($noTime, $good, $lock, Clients::browser())->outcome);
            self::assertSame([], $this->table->calls);

            self::assertSame(RecheckOutcome::PASSED, $recheck->recheck($withTime, $good, $lock, Clients::browser()));
            self::assertSame(RecheckOutcome::IDENTITY_MISMATCH, $recheck->recheck($withTime, $bind($this->person, $link->id, null, self::SESSION), $lock, Clients::browser()));
            $another = new IdentityReference('App\Models\User', '8');

            self::assertSame(RecheckOutcome::IDENTITY_MISMATCH, $recheck->recheck($withTime, $bind($this->person, $link->id, $another, self::SESSION), $lock, Clients::browser()));
            self::assertSame(RecheckOutcome::IDENTITY_MISMATCH, $recheck->recheck($withTime, $bind($this->person, null, $this->person, self::SESSION), $lock, Clients::browser()));

            try {
                $recheck->recheck($withTime, new HandoffBinding($this->person, $link->id, $this->person, trustVersion: 0), $lock, Clients::browser());
                self::fail('A binding naming no session was accepted.');
            } catch (\LogicException $exception) {
                self::assertSame('A reauthenticate flow names the session it was started on.', $exception->getMessage());
            }
        });
    }

    /**
     * Rows of what a binding or a result lacks, once a judgement would have
     * refused it: why `admit()` itself throws.
     *
     * @return iterable<string, array{0: bool, 1: bool, 2: bool, 3: string}>
     */
    public static function provideOutOfTurnAdmissions(): iterable
    {
        yield 'no identity' => [false, true, true, 'A reauthenticate flow names the identity it was started for.'];
        yield 'no session' => [true, false, true, 'A reauthenticate flow names the session it was started on.'];
        yield 'no authentication time' => [true, true, false, 'A reauthenticate result states when the provider authenticated.'];
    }

    /**
     * The branch's `admit()` runs only once `judge()` passed; called out of
     * turn with what `judge()` refuses, it throws rather than renew.
     *
     * @param  bool  $identity
     * @param  bool  $session
     * @param  bool  $time
     * @param  string  $message
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideOutOfTurnAdmissions')]
    public function testTheBranchRefusesToAdmitOutOfTurn(bool $identity, bool $session, bool $time, string $message): void
    {
        $link     = $this->hold($this->person);
        $sessions = $this->recording($link);
        $result   = $time ? $this->resultWith(new AuthenticationContext($this->clock->now())) : $this->resultWithNoTime();
        $binding  = new HandoffBinding($this->person, $link->id, $identity ? $this->person : null, $session ? self::SESSION : null, trustVersion: 0);

        DB::connection(StorageConnection::name())->transaction(function () use ($result, $binding, $message): void {

            $lock = app(HandoffRecheck::class)->lock('tenant-1', $this->connection->id, 'web');

            self::assertNotNull($lock->connection);

            try {
                app(ReauthenticationBranch::class)->admit(new RedemptionContext($result, $binding, $lock, $lock->connection, Clients::browser()));
                self::fail('The branch admitted out of turn.');
            } catch (\LogicException $exception) {
                self::assertSame($message, $exception->getMessage());
            }
        });

        self::assertSame(0, $sessions->renewals());
    }

    /**
     * The completion's rules refuse to judge a state they are not given, and a
     * request naming no identity is the pipeline's mistake.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheRulesRefuseAStateOutOfTurn(): void
    {
        $arrived = CompletionState::arrived($this->connection->id, new CompletionRequest('GET', '', []), Clients::browser());

        try {
            app(ReauthenticationRules::class)->refusal($arrived);
            self::fail('The rules judged a state with no request.');
        } catch (\LogicException $exception) {
            self::assertSame('A reauthentication is checked once its request is consumed.', $exception->getMessage());
        }

        try {
            app(ReauthenticationRules::class)->refusal($this->consumedState($arrived));
            self::fail('The rules judged a request naming no identity.');
        } catch (\LogicException $exception) {
            self::assertSame('A reauthenticate flow names the identity it was started for.', $exception->getMessage());
        }
    }

    /**
     * The completion's rules fail closed: a state with nothing resolved is
     * `identity_mismatch`, and a link of the identity with no result to judge
     * is `authentication_expired`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheRulesFailClosedOnAStateWithoutAResolutionOrAResult(): void
    {
        $arrived = CompletionState::arrived($this->connection->id, new CompletionRequest('GET', '', []), Clients::browser());
        $state   = $this->consumedState($arrived, ['identity_type' => $this->person->type, 'identity_id' => $this->person->id, 'session_id' => self::SESSION]);
        $rules   = app(ReauthenticationRules::class);

        self::assertSame(FailureReason::IDENTITY_MISMATCH, $rules->refusal($state));
        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, $rules->refusal($state->withResolution(LinkResolution::linked($this->person, 'link-1'))));
    }

    /**
     * Make a link of the subject for the identity, through the store.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  string  $subject
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function hold(IdentityReference $identity, LinkOrigin $origin = LinkOrigin::PROVISIONING, string $subject = VerifyingDriver::SUBJECT): Link
    {
        $creation = app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, $subject), $identity, $origin, Clients::browser());

        self::assertTrue($creation->isCreated());

        return Link::query()->whereKey($creation->link?->id)->sole();
    }

    /**
     * Bind the recording contract, with one session bound to the link.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @return \Tests\Fixtures\Linking\RecordingSessions
     */
    private function recording(Link $link): RecordingSessions
    {
        $sessions = new RecordingSessions($link->id);

        $this->app?->instance(ReauthenticationSessions::class, $sessions);

        return $sessions;
    }

    /**
     * Start and complete a `reauthenticate` on the session.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: \SineMacula\Laravel\Sso\Completion\CompletionResult}
     */
    private function flow(): array
    {
        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        return [$start, $completion];
    }

    /**
     * Redeem the completion's code through `admit()` for what is asked, inside
     * a transaction of the caller's.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  string  $connection
     * @param  string  $verifier
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function admitWith(CompletionResult $completion, Purpose $purpose, string $application, string $connection, string $verifier): RedemptionResult
    {
        $code = (string) $completion->handoff?->code->reveal();

        return DB::connection(StorageConnection::name())->transaction(
            static fn (): RedemptionResult => app(HandoffRedemption::class)->admit($purpose, $application, $connection, $code, $verifier, Clients::browser()),
        );
    }

    /**
     * What the driver verifies, authenticated at the instant.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @param  string  $subject
     * @return \SineMacula\Laravel\Sso\Results\VerifiedClaims
     */
    private function claimsAt(CarbonImmutable $at, string $subject = VerifyingDriver::SUBJECT): VerifiedClaims
    {
        return new VerifiedClaims(VerifyingDriver::ISSUER, $subject, null, ['mail' => self::EMAIL], new AuthenticationContext($at));
    }

    /**
     * A result of the flow's subject with no authentication time.
     *
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \Random\RandomException
     */
    private function resultWithNoTime(): VerifiedResult
    {
        return $this->resultWith(new AuthenticationContext);
    }

    /**
     * A `reauthenticate` result of the flow's subject with the context.
     *
     * @param  \SineMacula\Laravel\Sso\Results\AuthenticationContext  $context
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \Random\RandomException
     */
    private function resultWith(AuthenticationContext $context): VerifiedResult
    {
        return new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $this->connection->id,
            tenantId: 'tenant-1',
            protocol: VerifyingDriver::NAME,
            application: 'web',
            purpose: Purpose::REAUTHENTICATE,
            requestReference: RequestReference::generate(),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: $context,
        );
    }

    /**
     * The state once a `reauthenticate` request naming what is given is
     * consumed.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $arrived
     * @param  array<string, string>  $binding
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     *
     * @throws \Random\RandomException
     */
    private function consumedState(CompletionState $arrived, array $binding = []): CompletionState
    {
        $request  = $this->makeAuthorizationRequest($this->connection, ['purpose' => Purpose::REAUTHENTICATE] + $binding);
        $consumed = new ConsumedRequest(Purpose::REAUTHENTICATE, 'web', RequestReference::generate(), $this->clock->now());

        return $arrived->withAuthorizationRequest($request, $consumed, app(ApplicationGate::class)->admit('web')->application ?? self::fail('The application is admitted.'));
    }

    /**
     * Assert the redemption was refused for the reason with the code spent and
     * no sign-in acknowledged.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $answer
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return void
     */
    private function assertRefused(FailureReason $reason, RedemptionResult $answer, StartResult $start): void
    {
        self::assertSame([true, $reason, false], [$answer->isRefused(), $answer->reason, $answer->isAdmitted()]);
        self::assertNotNull($this->storedCode($start)->redeemed_at);
        self::assertFalse(Connection::query()->whereKey($this->connection->id)->sole()->has_completed_sign_in);
    }

    /**
     * The stored code of the flow.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Models\HandoffCode
     */
    private function storedCode(StartResult $start): StoredCode
    {
        return StoredCode::query()->where('request_reference', $start->reference?->value)->sole();
    }

    /**
     * Bind an evidence policy answering what is given, recording what it was
     * asked.
     *
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $accepted
     * @return object{asked: list<array{0: string, 1: string, 2: string}>}&\SineMacula\Laravel\Sso\Contracts\EvidencePolicy
     */
    private function policy(?AcceptedEvidence $accepted): EvidencePolicy
    {
        $policy = new class ($accepted) implements EvidencePolicy {
            /** @var list<array{0: string, 1: string, 2: string}> What it was asked: the reference, the connection and the instant. */
            public array $asked = [];

            /**
             * Constructor.
             *
             * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $accepted
             */
            public function __construct(

                /** What it answers. */
                private readonly ?AcceptedEvidence $accepted,
            ) {}

            /**
             * Record what it was asked, and answer.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \Carbon\CarbonImmutable  $now
             * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
             */
            #[\Override]
            public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): ?AcceptedEvidence
            {
                $this->asked[] = [$result->requestReference->value, $connection->getConnectionId(), $now->format('Y-m-d\TH:i:s.u\Z')];

                return $this->accepted;
            }
        };

        $this->app?->instance(EvidencePolicy::class, $policy);

        return $policy;
    }

    /**
     * The sessions table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function sessions(): Builder
    {
        return DB::connection(StorageConnection::name())->table(self::SESSIONS);
    }

    /**
     * The session's row as an array.
     *
     * @param  string  $session
     * @return array<string, mixed>
     */
    private function sessionRow(string $session): array
    {
        return (array) $this->sessions()->where('id', $session)->sole();
    }

    /**
     * Insert a session for the person, of the application and the connection,
     * bound to the link, and bind the contract over the table.
     *
     * @param  string  $session
     * @param  string  $linkId
     * @param  array<string, mixed>  $changes
     * @return void
     */
    private function tableSession(string $session, string $linkId, array $changes = []): void
    {
        $this->sessions()->insert($changes + [
            'id'               => $session,
            'identity_type'    => $this->person->type,
            'identity_id'      => $this->person->id,
            'application'      => 'web',
            'connection_id'    => $this->connection->id,
            'link_id'          => $linkId,
            'active'           => true,
            'authenticated_at' => self::EARLIER,
            'expires_at'       => '2026-11-01T20:00:00Z',
            'refresh_token'    => 'refresh-1',
            'provenance'       => 'sign-in-through-the-connection',
            'evidence'         => 'earlier-evidence',
        ]);

        if (isset($this->table)) {
            return;
        }

        $this->table = $this->tableContract();

        $this->app?->instance(ReauthenticationSessions::class, $this->table);
    }

    /**
     * A session contract over the table, comparing every value as an
     * implementation must, with a locking read, and recording each call with
     * the transaction level it ran at.
     *
     * @return object{calls: list<array<int, mixed>>, failing: ?string, failure: ?\Throwable}&\SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions
     */
    private function tableContract(): ReauthenticationSessions
    {
        return new class (fn (): Builder => $this->sessions()) implements ReauthenticationSessions {
            /** @var list<array<int, mixed>> Every call: its name, the transaction level, and its values. */
            public array $calls = [];

            /** @var ?string The call that fails. */
            public ?string $failing = null;

            /** @var ?\Throwable What it fails with, while set. */
            public ?\Throwable $failure = null;

            /**
             * Constructor.
             *
             * @param  \Closure(): \Illuminate\Database\Query\Builder  $rows
             */
            public function __construct(

                /** The table's rows. */
                private readonly \Closure $rows,
            ) {}

            /**
             * Whether the identity holds the active session through the
             * connection.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function standing(IdentityReference $identity, string $sessionId, SsoConnection $connection): SessionStanding
            {
                $this->record('standing', [$identity->type, $identity->id, $sessionId, $connection->getConnectionId()]);

                $row = ($this->rows)()->where('id', $sessionId)->first();

                return $this->matches($row, [$identity->type, $identity->id, $connection->getConnectionId()], ['identity_type', 'identity_id', 'connection_id']);
            }

            /**
             * Lock the session's row, and whether all five match.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  string  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  string  $linkId
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function lockedStanding(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection, string $linkId): SessionStanding
            {
                $this->record('lockedStanding', [$identity->type, $identity->id, $sessionId, $application, $connection->getConnectionId(), $linkId]);

                $row = ($this->rows)()->where('id', $sessionId)->lockForUpdate()->first();

                return $this->matches(
                    $row,
                    [$identity->type, $identity->id, $application, $connection->getConnectionId(), $linkId],
                    ['identity_type', 'identity_id', 'application', 'connection_id', 'link_id'],
                );
            }

            /**
             * Write the authentication time and any new evidence.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \Carbon\CarbonImmutable  $authenticatedAt
             * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
             * @return void
             */
            #[\Override]
            public function renewAuthentication(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void
            {
                $at = $authenticatedAt->utc()->format('Y-m-d\TH:i:s.u\Z');

                $this->record('renewAuthentication', [$identity->type, $identity->id, $sessionId, $at, $evidence]);

                $row     = ($this->rows)()->where('id', $sessionId)->first();
                $earlier = is_object($row) && is_string($row->evidence ?? null) ? $row->evidence : '';

                ($this->rows)()->where('id', $sessionId)->update([
                    'authenticated_at' => $at,
                    'evidence'         => $evidence === null ? $earlier : $earlier . ',' . $evidence->connectionId,
                ]);
            }

            /**
             * Whether the row is active with each column the value given.
             *
             * @param  ?object  $row
             * @param  list<string>  $values
             * @param  list<string>  $columns
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            private function matches(?object $row, array $values, array $columns): SessionStanding
            {
                $read = (array) $row;
                $held = $row === null ? [] : array_map(static fn (string $column): mixed => $read[$column] ?? null, $columns);

                return $row !== null && (bool) ($row->active ?? false) && $held === $values ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
            }

            /**
             * Record the call, and fail when it is the one set to.
             *
             * @param  string  $call
             * @param  list<mixed>  $values
             * @return void
             *
             * @throws \Throwable
             */
            private function record(string $call, array $values): void
            {
                $this->calls[] = [$call, DB::connection(StorageConnection::name())->transactionLevel(), ...$values];

                if ($this->failing === $call && $this->failure !== null) {
                    throw $this->failure;
                }
            }
        };
    }
}
