<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningResult;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Query budgets of the provisioning boundary (SSO-8.6, SSO-11.8), each measured
 * once the IP address's and the connection's counters exist, over the package's
 * link store and an issuer that costs nothing:
 *
 * - a completion that crosses the boundary and ends unlinked adds to an
 *   ordinary completion the link's locking read and the request's `verified_at`
 *   in its preparation, T2, and in its final continuation, T3, the connection's
 *   and the request's locks and the link's read again;
 * - the helper locks the connection, the request and the subject's row, and
 *   then the store locks the connection again, counts the identity's links and
 *   looks for an expired reservation; it writes the link and the links version;
 * - T3 then finds the link, and stamps its last use;
 * - a refusal writes nothing, and stops at what it needed: a spent grant reads
 *   nothing; a disabled connection and a passed deadline read the two locks; a
 *   held subject its row too; a limit reached the store's two reads more;
 * - with enforcement on, each of T2, the helper and T3 first upserts and locks
 *   the tenant's enforcement row, and locks the connection with the rule's
 *   connections in the one statement that locked it alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProvisioningHelper::class)]
#[CoversClass(CompletionPipeline::class)]
final class ProvisioningQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-budgeted-request-1';

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity provisioned. */
    private IdentityReference $person;

    /** @var int How many budgets the listener measured. */
    private int $measured = 0;

    /**
     * Bind the link store, the recording issuer and a request from an IP
     * address, register the application and the driver, make a usable
     * connection that maps the email, create the counters, and store the
     * request.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->person = new IdentityReference('App\Models\User', '42');

        $this->app?->instance(HandoffIssuer::class, new RecordingHandoffIssuer);
        $this->app?->instance(Linker::class, app(LinkStore::class));
        $this->app?->instance('request', Request::create('/auth/sso/connections/x/callback', 'GET', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $driver = new VerifyingDriver;

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->connection = $this->makeConnection([
            'protocol'          => VerifyingDriver::NAME,
            'enabled'           => true,
            'settings'          => ['issuer' => VerifyingDriver::ISSUER],
            'attribute_mapping' => ['email' => 'mail'],
        ]);

        $this->completeAtCallback('a-state-that-creates-the-counters');

        $this->makeAuthorizationRequest($this->connection, [
            'state_digest'      => hash('sha256', self::STATE),
            'handoff_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_verifier'     => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-budgeted-request-1'),
        ]);
    }

    /**
     * Crossing the boundary and ending unlinked is ten reads and six writes.
     *
     * @return void
     */
    public function testABoundaryCrossedAndEndingUnlinkedIsTenReadsAndSixWrites(): void
    {
        $result = $this->assertQueryBudget(10, 6, fn (): CompletionResult => $this->completeAtCallback(self::STATE));

        self::assertSame(FailureReason::UNLINKED, $result->reason);
    }

    /**
     * Provisioned, the whole completion is sixteen reads and nine writes.
     *
     * @return void
     */
    public function testAProvisionedCompletionIsSixteenReadsAndNineWrites(): void
    {
        $this->provisionOnOffer();

        $result = $this->assertQueryBudget(16, 9, fn (): CompletionResult => $this->completeAtCallback(self::STATE));

        self::assertTrue($result->isCompleted());
    }

    /**
     * Under enforcement, ending unlinked is twelve reads and eight writes, and
     * provisioned nineteen reads and twelve writes.
     *
     * @return void
     */
    public function testUnderEnforcementEachTransactionTakesTheGuard(): void
    {
        config()->set('sso.features.enforcement', true);

        $unlinked = $this->assertQueryBudget(12, 8, fn (): CompletionResult => $this->completeAtCallback(self::STATE));

        self::assertSame(FailureReason::UNLINKED, $unlinked->reason);

        $this->makeAuthorizationRequest($this->connection, [
            'state_digest'      => hash('sha256', 'a-second-state'),
            'handoff_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_verifier'     => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-budgeted-request-2'),
        ]);

        $this->provisionOnOffer();

        $provisioned = $this->assertQueryBudget(19, 12, fn (): CompletionResult => $this->completeAtCallback('a-second-state'));

        self::assertTrue($provisioned->isCompleted());
    }

    /**
     * The helper alone is six reads and two writes.
     *
     * @return void
     */
    public function testTheHelperIsSixReadsAndTwoWrites(): void
    {
        $this->measureOnOffer(6, 2, ProvisioningStatus::CREATED);

        $this->completeAtCallback(self::STATE);

        self::assertSame(1, $this->measured);
    }

    /**
     * Under enforcement, the helper is seven reads and three writes.
     *
     * @return void
     */
    public function testUnderEnforcementTheHelperIsSevenReadsAndThreeWrites(): void
    {
        config()->set('sso.features.enforcement', true);

        $this->measureOnOffer(7, 3, ProvisioningStatus::CREATED);

        $this->completeAtCallback(self::STATE);

        self::assertSame(1, $this->measured);
    }

    /**
     * A disabled connection stops at the two locks, and writes nothing.
     *
     * @return void
     */
    public function testAConnectionNoLongerUsableStopsAtTheLocks(): void
    {
        $this->measureOnOffer(2, 0, ProvisioningStatus::REQUEST_UNAVAILABLE, function (): void {
            $this->connection->forceFill(['enabled' => false])->save();
        });

        $this->completeAtCallback(self::STATE);

        self::assertSame(1, $this->measured);
    }

    /**
     * A passed deadline stops at the two locks, and writes nothing.
     *
     * @return void
     */
    public function testAPassedDeadlineStopsAtTheLocks(): void
    {
        $this->measureOnOffer(2, 0, ProvisioningStatus::EXPIRED, function (): void {
            $this->clock->advance(120);
        });

        $this->completeAtCallback(self::STATE);

        self::assertSame(1, $this->measured);
    }

    /**
     * A held subject stops at its row, and writes nothing.
     *
     * @return void
     */
    public function testAHeldSubjectStopsAtItsRow(): void
    {
        $subject = new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT);

        $this->measureOnOffer(3, 0, ProvisioningStatus::SUBJECT_ALREADY_LINKED, function () use ($subject): void {
            app(LinkStore::class)->create($this->connection, $subject, new IdentityReference('App\Models\User', '43'), LinkOrigin::LINK_PURPOSE, Clients::browser());
        });

        $this->completeAtCallback(self::STATE);

        self::assertSame(1, $this->measured);
    }

    /**
     * A limit reached stops at the identity's links, and writes nothing.
     *
     * @return void
     */
    public function testALimitReachedStopsAtTheIdentitysLinks(): void
    {
        app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, 'another-subject'), $this->person, LinkOrigin::LINK_PURPOSE, Clients::browser());

        $this->measureOnOffer(5, 0, ProvisioningStatus::LINK_LIMIT_REACHED);

        $this->completeAtCallback(self::STATE);

        self::assertSame(1, $this->measured);
    }

    /**
     * A grant already spent reads and writes nothing.
     *
     * @return void
     */
    public function testASpentGrantCostsNothing(): void
    {
        Event::listen(ResultUnlinked::class, function (ResultUnlinked $event): void {

            $helper = app(ProvisioningHelper::class);

            $helper->link($event->grant, $event->result, $this->person, Clients::browser());

            $answer = $this->assertQueryBudget(0, 0, fn (): ProvisioningResult => $helper->link($event->grant, $event->result, $this->person, Clients::browser()));

            self::assertSame(ProvisioningStatus::GRANT_INVALID, $answer->status);

            $this->measured++;
        });

        $this->completeAtCallback(self::STATE);

        self::assertSame(1, $this->measured);
    }

    /**
     * Have the listener link the result.
     *
     * @return void
     */
    private function provisionOnOffer(): void
    {
        Event::listen(ResultUnlinked::class, function (ResultUnlinked $event): void {
            app(ProvisioningHelper::class)->link($event->grant, $event->result, $this->person, Clients::browser());
        });
    }

    /**
     * Have the listener make what is arranged, then assert what the helper
     * costs and answers.
     *
     * @param  int  $reads
     * @param  int  $writes
     * @param  \SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus  $status
     * @param  ?\Closure(): void  $arrange
     * @return void
     */
    private function measureOnOffer(int $reads, int $writes, ProvisioningStatus $status, ?\Closure $arrange = null): void
    {
        Event::listen(ResultUnlinked::class, function (ResultUnlinked $event) use ($reads, $writes, $status, $arrange): void {

            if ($arrange !== null) {
                $arrange();
            }

            $answer = $this->assertQueryBudget(
                $reads,
                $writes,
                fn (): ProvisioningResult => app(ProvisioningHelper::class)->link($event->grant, $event->result, $this->person, Clients::browser()),
            );

            self::assertSame($status, $answer->status);

            $this->measured++;
        });
    }

    /**
     * Complete at the callback with the state in the query.
     *
     * @param  string  $state
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function completeAtCallback(string $state): CompletionResult
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
}
