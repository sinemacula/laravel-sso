<?php

declare(strict_types = 1);

namespace Tests\Integration\Process;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\ProvisioningOffer;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Metadata\TransitionReceipts;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;
use SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\FailsDatabaseStatements;
use Tests\Concerns\FlowRoutes;
use Tests\Concerns\RunsLongLivedApplication;
use Tests\Fixtures\Clients;
use Tests\TestCase;

/**
 * Integration tests for one Octane worker serving requests for different
 * tenants.
 *
 * Only the worker's lifecycle runs between requests; nothing of a flow may stay
 * reachable after it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(ProvisioningGrant::class)]
#[CoversClass(ProvisioningHelper::class)]
#[CoversClass(ProvisioningOffer::class)]
#[CoversClass(TransitionReceipts::class)]
#[CoversClass(SsoServiceProvider::class)]
final class ConsecutiveRequestsTest extends TestCase
{
    use FailsDatabaseStatements, FlowRoutes, RunsLongLivedApplication;

    /** @var string The tenant of the OIDC connection A. */
    private const string TENANT_A = 'tenant-alpha-consecutive';

    /** @var string The tenant of the SAML connection B. */
    private const string TENANT_B = 'tenant-bravo-consecutive';

    /** @var string The tenant of the OIDC connection C, which shares A's `kid`. */
    private const string TENANT_C = 'tenant-charlie-consecutive';

    /** @var string The subject A's provider asserts. */
    private const string SUBJECT_A = 'subject-alpha-consecutive';

    /** @var string The `NameID` B's provider asserts. */
    private const string SUBJECT_B = 'subject-bravo-consecutive';

    /** @var string The email A's provider asserts. */
    private const string EMAIL_A = 'alpha-consecutive@example.com';

    /** @var string The email B's provider asserts. */
    private const string EMAIL_B = 'bravo-consecutive@example.com';

    /** @var \SineMacula\Laravel\Sso\Models\Connection A: OIDC, RS256 alone. */
    private Connection $connectionA;

    /** @var \SineMacula\Laravel\Sso\Models\Connection B: SAML. */
    private Connection $connectionB;

    /** @var \SineMacula\Laravel\Sso\Models\Connection C: OIDC, PS256 alone, under A's `kid` with another key. */
    private Connection $connectionC;

    /** @var list<string> Every value of a flow so far, none of which any later request may reach. */
    private array $flowValues = [];

    /**
     * Create the three connections and boot the one worker on the root
     * application.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->prepareFlows();
        $this->usePackageTables();
        $this->registerFlowRoutes();

        Route::get('/sso/throw', static function (): never {
            throw new \RuntimeException('The route failed.');
        });

        $this->connectionA = $this->flowOidcConnection(self::TENANT_A, 'op-alpha', self::flowKey('alpha'), 'RS256');
        $this->connectionB = $this->flowSamlConnection(self::TENANT_B, 'idp-bravo');
        $this->connectionC = $this->flowOidcConnection(self::TENANT_C, 'op-charlie', self::flowKey('charlie'), 'PS256');

        $this->flowValues = [
            self::TENANT_A,
            self::TENANT_B,
            self::TENANT_C,
            self::SUBJECT_A,
            self::SUBJECT_B,
            self::EMAIL_A,
            self::EMAIL_B,
            $this->connectionA->id,
            $this->connectionB->id,
            $this->connectionC->id,
        ];

        $this->bootLongLivedWorker();
    }

    /**
     * A then B then A each complete for their own tenant, and nothing stays.
     *
     * @return void
     */
    public function testEachTenantIsServedItsOwnResultAcrossAThenBThenA(): void
    {
        $first  = $this->signInThroughA();
        $second = $this->signInThroughB();
        $third  = $this->signInThroughA();

        self::assertSame([self::TENANT_A, self::SUBJECT_A, $this->connectionA->id], [$first['tenant'], $first['subject'], $first['connection']]);
        self::assertSame([self::TENANT_B, $this->connectionB->id], [$second['tenant'], $second['connection']]);
        self::assertStringContainsString(self::SUBJECT_B, self::flowText($second['subject']));
        self::assertSame([self::TENANT_A, self::SUBJECT_A, $this->connectionA->id], [$third['tenant'], $third['subject'], $third['connection']]);
        self::assertNotSame($first['reference'], $third['reference']);
    }

    /**
     * Interleaved flows each find their own request and code.
     *
     * @return void
     */
    public function testInterleavedFlowsKeepTheirOwnState(): void
    {
        $startB = $this->startInWorker($this->connectionB);
        $startA = $this->startInWorker($this->connectionA);

        $codeB = $this->completedInWorker($this->connectionB, $startB, self::samlPerson());
        $codeA = $this->completedInWorker($this->connectionA, $startA, self::oidcPerson());

        $redeemedB = $this->redeemInWorker($this->connectionB, $codeB, $startB['verifier']);
        $redeemedA = $this->redeemInWorker($this->connectionA, $codeA, $startA['verifier']);

        self::assertSame([self::TENANT_B, $startB['reference']], [$redeemedB->json('tenant'), $redeemedB->json('reference')]);
        self::assertSame([self::TENANT_A, $startA['reference'], self::SUBJECT_A], [$redeemedA->json('tenant'), $redeemedA->json('reference'), $redeemedA->json('subject')]);
    }

    /**
     * One tenant's answer or code is `connection_mismatch` at another.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testOneTenantsValuesServeNoOther(): void
    {
        $startA = $this->startInWorker($this->connectionA);
        $grant  = $this->flowGrant($this->connectionA, $startA, self::oidcPerson());

        $this->assertFailedFlow($this->inWorker(fn (): TestResponse => $this->deliverGrant($this->connectionC, $grant)), FailureReason::CONNECTION_MISMATCH);

        $startA = $this->startInWorker($this->connectionA);
        $code   = $this->completedInWorker($this->connectionA, $startA, self::oidcPerson());

        $wrong = $this->inWorker(fn (): TestResponse => $this->flowRedeem($this->connectionB, 'sign_in', $code, $startA['verifier']));

        $wrong->assertStatus(422);

        self::assertSame(FailureReason::CONNECTION_MISMATCH->value, $wrong->json('reason'));
        self::assertSame(self::TENANT_B, $this->signInThroughB()['tenant']);
    }

    /**
     * A refusal under a shared `kid` leaves nothing for the next request.
     *
     * @return void
     */
    public function testARefusalBetweenSuccessesLeavesNothing(): void
    {
        self::assertSame(self::SHARED_KID, self::flowKey('alpha')->jwk()['kid'] ?? null);
        self::assertSame(self::SHARED_KID, self::flowKey('charlie')->jwk()['kid'] ?? null);

        $this->signInThroughA();

        $signedWithAsKey = static fn (FakeIdToken $token): FakeIdToken => $token->signedWith(self::flowKey('alpha'), 'PS256');

        $startC = $this->startInWorker($this->connectionC);

        $this->assertFailedFlow($this->inWorker(fn (): TestResponse => $this->completeFlow($this->connectionC, $startC, $signedWithAsKey)), FailureReason::SIGNATURE_INVALID);

        self::assertSame(self::TENANT_C, $this->signedInInWorker($this->connectionC)['tenant']);

        $startA = $this->startInWorker($this->connectionA);

        $this->assertFailedFlow($this->inWorker(fn (): TestResponse => $this->completeFlow($this->connectionA, $startA, $signedWithAsKey)), FailureReason::SIGNATURE_INVALID);

        self::assertSame(self::TENANT_A, $this->signInThroughA()['tenant']);
    }

    /**
     * A SAML refusal between two OIDC successes leaves nothing behind.
     *
     * @return void
     */
    public function testARefusedResponseIssuesNothing(): void
    {
        $this->signInThroughA();

        $codes  = HandoffCode::query()->useWritePdo()->count();
        $startB = $this->startInWorker($this->connectionB);
        $tailor = static fn (FakeSamlResponse $response): FakeSamlResponse => $response->signed(false, false);

        $this->assertFailedFlow($this->inWorker(fn (): TestResponse => $this->completeFlow($this->connectionB, $startB, $tailor)), FailureReason::SIGNATURE_INVALID);

        self::assertSame($codes, HandoffCode::query()->useWritePdo()->count());
        self::assertSame(self::TENANT_A, $this->signInThroughA()['tenant']);
    }

    /**
     * A route that throws is a 500 and the next request runs normally.
     *
     * @return void
     */
    public function testARouteThatThrowsIsAServerErrorAndTheNextRequestRuns(): void
    {
        $this->signInThroughA();

        $this->inWorker(fn (): TestResponse => $this->sendFlowRequest('GET', '/sso/throw'))->assertStatus(500);

        self::assertSame(self::TENANT_B, $this->signInThroughB()['tenant']);

        $this->inWorker(fn (): TestResponse => $this->sendFlowRequest('GET', '/sso/throw'))->assertStatus(500);

        self::assertSame(self::TENANT_A, $this->signInThroughA()['tenant']);
    }

    /**
     * A failed statement is a 500 and its transaction is gone by the next
     * request.
     *
     * @return void
     */
    public function testAFailedStatementIsAServerErrorAndTheNextRequestRuns(): void
    {
        $startB = $this->startInWorker($this->connectionB);

        $this->failStatement(self::onTable('update', StorageConnection::table('authorization_requests.table')));

        $this->inWorker(fn (): TestResponse => $this->completeFlow($this->connectionB, $startB, self::samlPerson()))->assertStatus(500);

        self::assertSame(1, $this->databaseFailuresFired());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertNull(AuthorizationRequest::query()->useWritePdo()->where('reference', $startB['reference'])->sole()->consumed_at);

        self::assertSame(self::TENANT_A, $this->signInThroughA()['tenant']);

        $code = $this->completedInWorker($this->connectionB, $startB, self::samlPerson());

        self::assertSame(self::TENANT_B, $this->redeemInWorker($this->connectionB, $code, $startB['verifier'])->json('tenant'));
    }

    /**
     * A's grant opens nothing in B's request.
     *
     * @return void
     */
    public function testAGrantFromTheLastRequestIsRefusedInTheNext(): void
    {
        $identityA = new IdentityReference('App\Models\User', 'identity-alpha-consecutive');
        $identityB = new IdentityReference('App\Models\User', 'identity-bravo-consecutive');

        /** @var ?\SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant $grantA */
        $grantA = null;

        /** @var ?\SineMacula\Laravel\Sso\Results\VerifiedResult $resultA */
        $resultA = null;

        $attempts = [];
        $usable   = null;
        $linked   = null;

        $listener = static function (ResultUnlinked $event) use (&$grantA, &$resultA, &$attempts, &$usable, &$linked, $identityA, $identityB): void {

            if ($grantA === null || $resultA === null) {

                $grantA  = $event->grant;
                $resultA = $event->result;

                return;
            }

            $helper = app(ProvisioningHelper::class);

            $attempts[] = $helper->link($grantA, $event->result, $identityA, Clients::browser())->status;
            $attempts[] = $helper->link($grantA, $resultA, $identityA, Clients::browser())->status;
            $usable     = $event->grant->isUsable();
            $linked     = $helper->link($event->grant, $event->result, $identityB, Clients::browser())->isCreated();
        };

        Event::listen(ResultUnlinked::class, $listener);

        $this->signInThroughA();

        self::assertInstanceOf(ProvisioningGrant::class, $grantA);
        self::assertFalse($grantA->isUsable());

        $answer = $this->signInThroughB();

        self::assertSame([ProvisioningStatus::GRANT_INVALID, ProvisioningStatus::GRANT_INVALID], $attempts);
        self::assertSame([true, true], [$usable, $linked]);
        self::assertSame($identityB->jsonSerialize(), $answer['linked']);
        self::assertSame(1, Link::query()->useWritePdo()->where('connection_id', $this->connectionB->id)->where('identity_id', $identityB->id)->count());
        self::assertSame(0, Link::query()->useWritePdo()->where('identity_id', $identityA->id)->count());
    }

    /**
     * A grant, used or not, is refused once its request is over.
     *
     * @return void
     */
    public function testAGrantIsSpentWhenItsRequestEnds(): void
    {
        $identity = new IdentityReference('App\Models\User', 'identity-spent-consecutive');

        /** @var list<\SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant> $grants */
        $grants = [];

        /** @var list<\SineMacula\Laravel\Sso\Results\VerifiedResult> $results */
        $results = [];

        $linkFirst = true;

        Event::listen(ResultUnlinked::class, static function (ResultUnlinked $event) use (&$grants, &$results, &$linkFirst, $identity): void {

            $grants[]  = $event->grant;
            $results[] = $event->result;

            if ($linkFirst) {
                self::assertTrue(app(ProvisioningHelper::class)->link($event->grant, $event->result, $identity, Clients::browser())->isCreated());
            }

            $linkFirst = false;
        });

        $this->signInThroughB();
        $this->signInThroughA();

        self::assertCount(2, $grants);

        foreach ($grants as $index => $grant) {
            self::assertFalse($grant->isUsable());
            self::assertSame(ProvisioningStatus::GRANT_INVALID, app(ProvisioningHelper::class)->link($grant, $results[$index], $identity, Clients::browser())->status);
        }

        self::assertSame(1, Link::query()->useWritePdo()->where('identity_id', $identity->id)->count());
    }

    /**
     * A listener that throws is a 500 and voids the grant it held.
     *
     * @return void
     */
    public function testAGrantHeldByAListenerThatThrowsIsVoid(): void
    {
        /** @var ?\SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant $held */
        $held     = null;
        $throwing = true;
        $identity = new IdentityReference('App\Models\User', 'identity-thrown-consecutive');

        /** @var ?\SineMacula\Laravel\Sso\Results\VerifiedResult $result */
        $result = null;

        Event::listen(ResultUnlinked::class, static function (ResultUnlinked $event) use (&$held, &$throwing, &$result): void {

            if (!$throwing) {
                return;
            }

            $throwing = false;
            $held     = $event->grant;
            $result   = $event->result;

            throw new \RuntimeException('The listener failed.');
        });

        $start = $this->startInWorker($this->connectionA);

        $this->inWorker(fn (): TestResponse => $this->completeFlow($this->connectionA, $start, self::oidcPerson()))->assertStatus(500);

        self::assertInstanceOf(ProvisioningGrant::class, $held);
        self::assertInstanceOf(VerifiedResult::class, $result);
        self::assertFalse($held->isUsable());
        self::assertSame(ProvisioningStatus::GRANT_INVALID, app(ProvisioningHelper::class)->link($held, $result, $identity, Clients::browser())->status);
        self::assertSame(0, Link::query()->useWritePdo()->where('identity_id', $identity->id)->count());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame(self::TENANT_B, $this->signInThroughB()['tenant']);
    }

    /**
     * A's receipt permits only A's own finish, never another tenant's.
     *
     * @return void
     */
    public function testAReceiptFromTheLastRequestIsRefusedInTheNext(): void
    {
        $next = self::flowKey('alpha-next', 'rotated-kid');

        $this->flowProvider($this->connectionA)->unpublish(self::SHARED_KID)->publish($next)->signWith($next);

        /** @var ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt $receipt */
        $receipt = null;

        $own       = null;
        $permitted = [];
        $forged    = [];
        $untouched = [];

        $listener = static function (ResultUnlinked $event) use (&$receipt, &$own, &$permitted, &$forged, &$untouched): void {

            if ($receipt === null) {

                $receipt = $event->grant->transitionReceipt();

                self::assertInstanceOf(TransitionReceipt::class, $receipt);

                $own = TransitionReceipts::permits(
                    $receipt,
                    Connection::query()->useWritePdo()->findOrFail($receipt->connectionId),
                    AuthorizationRequest::query()->useWritePdo()->findOrFail($receipt->requestId),
                );

                return;
            }

            $request    = AuthorizationRequest::query()->useWritePdo()->where('reference', $event->result->requestReference->value)->sole();
            $connection = Connection::query()->useWritePdo()->findOrFail($event->result->connectionId);

            $connection->forceFill(['trust_version' => $receipt->toTrustVersion, 'jwks_version' => $receipt->jwksVersion]);
            $request->forceFill(['trust_version' => $receipt->fromTrustVersion]);

            $permitted[] = TransitionReceipts::permits($receipt, $connection, $request);

            $grant = ProvisioningGrant::issue($event->result, $request->id, $event->grant->verifiedUntil(), $receipt);

            $forged[] = app(ProvisioningHelper::class)->link(
                $grant,
                $event->result,
                new IdentityReference('App\Models\User', 'identity-forged-consecutive'),
                Clients::browser(),
            )->status;
            $untouched[] = $event->grant->isUsable();
        };

        Event::listen(ResultUnlinked::class, $listener);

        self::assertSame(self::TENANT_A, $this->signedInInWorker($this->connectionA, self::oidcPerson())['tenant']);

        self::assertInstanceOf(TransitionReceipt::class, $receipt);
        self::assertTrue($own);

        self::assertSame(self::TENANT_C, $this->signedInInWorker($this->connectionC)['tenant']);
        self::assertSame(self::TENANT_B, $this->signInThroughB()['tenant']);

        self::assertSame([false, false], $permitted);
        self::assertSame([ProvisioningStatus::GRANT_INVALID, ProvisioningStatus::GRANT_INVALID], $forged);
        self::assertSame([true, true], $untouched);
        self::assertSame(0, Link::query()->useWritePdo()->where('identity_id', 'identity-forged-consecutive')->count());

        self::assertFalse(TransitionReceipts::permits(
            $receipt,
            Connection::query()->useWritePdo()->findOrFail($receipt->connectionId),
            AuthorizationRequest::query()->useWritePdo()->findOrFail($receipt->requestId),
        ));
    }

    /**
     * A's rotation voids only A's flow in flight.
     *
     * @return void
     */
    public function testARotationOfOneTenantLeavesTheOthersFlowsInFlight(): void
    {
        $startA = $this->startInWorker($this->connectionA);
        $startB = $this->startInWorker($this->connectionB);
        $startC = $this->startInWorker($this->connectionC);

        $next = self::flowKey('alpha-next', 'rotated-kid');

        $this->flowProvider($this->connectionA)->unpublish(self::SHARED_KID)->publish($next)->signWith($next);

        $trigger = $this->startInWorker($this->connectionA);

        $this->completedInWorker($this->connectionA, $trigger, self::oidcPerson());

        self::assertNotNull(AuthorizationRequest::query()->useWritePdo()->where('reference', $startA['reference'])->sole()->voided_at);
        self::assertNull(AuthorizationRequest::query()->useWritePdo()->where('reference', $startB['reference'])->sole()->voided_at);
        self::assertNull(AuthorizationRequest::query()->useWritePdo()->where('reference', $startC['reference'])->sole()->voided_at);

        $this->completedInWorker($this->connectionB, $startB, self::samlPerson());
        $this->completedInWorker($this->connectionC, $startC);
    }

    /**
     * Neither the verified result nor the grant outlives its request.
     *
     * @return void
     */
    public function testAResultAndAGrantDoNotOutliveTheirRequest(): void
    {
        /** @var list<\WeakReference<object>> $references */
        $references = [];

        Event::listen(ResultUnlinked::class, static function (ResultUnlinked $event) use (&$references): void {
            $references[] = \WeakReference::create($event->grant);
            $references[] = \WeakReference::create($event->result);
        });

        $start = $this->startInWorker($this->connectionA);

        $this->completedInWorker($this->connectionA, $start, self::oidcPerson());

        gc_collect_cycles();

        self::assertCount(2, $references);

        foreach ($references as $reference) {
            self::assertNull($reference->get());
        }
    }

    /**
     * The retention check notices each secret a flow holds in memory.
     *
     * @return void
     */
    public function testARetainedSecretOfAFlowIsNoticed(): void
    {
        $startA = $this->startInWorker($this->connectionA);
        $startB = $this->startInWorker($this->connectionB);
        $query  = self::queryOf($startA);

        $secrets = [
            $startA['verifier'],
            self::flowText($query['state']),
            self::flowText($query['nonce']),
            self::relayStateOf($startB),
            $this->completedInWorker($this->connectionA, $startA, self::oidcPerson()),
        ];

        foreach ($secrets as $secret) {
            $this->app?->instance('sso.test.kept', new IdentityReference('App\Models\User', $secret));

            self::assertSame(['sso.test.kept->id'], $this->retainedBy($this->flowValues));
        }

        $this->app?->forgetInstance('sso.test.kept');

        $this->assertNothingRetained();
    }

    /**
     * Send the request to the one worker.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  array<string, mixed>  $parameters
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    protected function sendFlowRequest(string $method, string $uri, array $parameters = []): TestResponse
    {
        return $this->serve(self::workerRequest($method, $uri, $parameters));
    }

    /**
     * Start in the worker and track the flow's values as secrets.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return array{reference: string, verifier: string, navigation: array{type: string, url: string}}
     */
    private function startInWorker(Connection $connection): array
    {
        $start = $this->startedFlow($connection);
        $row   = AuthorizationRequest::query()->useWritePdo()->where('reference', $start['reference'])->sole();

        $this->flowValues = [...$this->flowValues, $start['reference'], $start['verifier'], $row->state_digest, ...self::secretsOf($connection, $start)];

        if ($row->nonce_digest !== null) {
            $this->flowValues[] = $row->nonce_digest;
        }

        $this->assertNothingRetained();

        return $start;
    }

    /**
     * Complete the flow in the worker, track its code, and answer it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array{reference: string, verifier: string, navigation: array{type: string, url: string}}  $start
     * @param  ?\Closure(never): mixed  $tailor
     * @return string
     */
    private function completedInWorker(Connection $connection, array $start, ?\Closure $tailor = null): string
    {
        $code = $this->completedCode($this->inWorker(fn (): TestResponse => $this->completeFlow($connection, $start, $tailor)));

        $this->flowValues[] = $code;

        $this->assertNothingRetained();

        return $code;
    }

    /**
     * The OIDC state and nonce, or the SAML relay state, the start sent.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array{reference: string, verifier: string, navigation: array{type: string, url: string}}  $start
     * @return list<string>
     */
    private static function secretsOf(Connection $connection, array $start): array
    {
        if ($connection->protocol === 'saml2') {
            return [self::relayStateOf($start)];
        }

        $query = self::queryOf($start);

        self::assertNotSame('', self::flowText($query['state'] ?? null));
        self::assertNotSame('', self::flowText($query['nonce'] ?? null));

        return [self::flowText($query['state']), self::flowText($query['nonce'])];
    }

    /**
     * Run the request in the worker, and assert nothing of a flow stayed.
     *
     * @param  \Closure(): \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $request
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function inWorker(\Closure $request): TestResponse
    {
        $response = $request();

        $this->assertNothingRetained();

        return $response;
    }

    /**
     * Redeem a `sign_in` code in the worker.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $code
     * @param  string  $verifier
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function redeemInWorker(Connection $connection, string $code, string $verifier): TestResponse
    {
        return $this->inWorker(fn (): TestResponse => $this->flowRedeem($connection, 'sign_in', $code, $verifier))->assertOk();
    }

    /**
     * One whole `sign_in` through the connection, in the worker.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\Closure(never): mixed  $tailor
     * @return array<string, mixed>
     */
    private function signedInInWorker(Connection $connection, ?\Closure $tailor = null): array
    {
        $start = $this->startInWorker($connection);
        $code  = $this->completedInWorker($connection, $start, $tailor);

        /** @var array<string, mixed> */
        return $this->redeemInWorker($connection, $code, $start['verifier'])->json();
    }

    /**
     * One whole `sign_in` of A's person.
     *
     * @return array<string, mixed>
     */
    private function signInThroughA(): array
    {
        return $this->signedInInWorker($this->connectionA, self::oidcPerson());
    }

    /**
     * One whole `sign_in` of B's person.
     *
     * @return array<string, mixed>
     */
    private function signInThroughB(): array
    {
        return $this->signedInInWorker($this->connectionB, self::samlPerson());
    }

    /**
     * What A's provider asserts: A's subject and email.
     *
     * @return \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken
     */
    private static function oidcPerson(): \Closure
    {
        return static fn (FakeIdToken $token): FakeIdToken => $token->with('sub', self::SUBJECT_A)->with('email', self::EMAIL_A);
    }

    /**
     * What B's provider asserts: B's `NameID` and email.
     *
     * @return \Closure(\SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse): \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private static function samlPerson(): \Closure
    {
        return static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['name_id' => self::SUBJECT_B, 'attributes' => ['email' => [self::EMAIL_B]]]);
    }

    /**
     * Assert no flow value is held by the root application or a static
     * property.
     *
     * @return void
     */
    private function assertNothingRetained(): void
    {
        self::assertSame([], $this->retainedBy($this->flowValues));
        self::assertSame([], $this->retainedByStatics($this->flowValues));
    }
}
