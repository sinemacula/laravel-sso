<?php

declare(strict_types = 1);

namespace Tests\Feature\Flows;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\ConsumptionResult;
use SineMacula\Laravel\Sso\Flows\Enums\ConsumptionStatus;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestConsumption;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Secrets\CountingSecretEncrypter;
use Tests\TestCase;

/**
 * Feature tests for consuming the authorisation request a response answers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestConsumption::class)]
#[CoversClass(ConsumptionResult::class)]
final class RequestConsumptionTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-request-0123456789';

    /** @var string The nonce the request was started with. */
    private const string NONCE = 'the-nonce-of-the-request-0123456789abcdefgh';

    /** @var string The PKCE verifier the request was started with. */
    private const string PKCE_VERIFIER = 'the-pkce-verifier-of-the-request-0123456789';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Rq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var string The SAML request id the request was started with. */
    private const string SAML_REQUEST_ID = '_a3f9c2e1-request';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the requests were started through. */
    private Connection $connection;

    /**
     * Bind a fixed clock, register the application, create the tables and a
     * connection, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);

        config()->set('sso.applications', [
            'web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
        ]);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['enabled' => true]);

        $this->startRecordingEvents();
    }

    /**
     * A request found by its state is consumed, recorded until its expiry and
     * handed on, reporting nothing.
     *
     * @return void
     */
    public function testARequestIsConsumedByItsState(): void
    {
        $request = $this->request([
            'expected_issuer' => 'https://idp.example.com',
            'issuer_required' => true,
            'saml_request_id' => self::SAML_REQUEST_ID,
        ]);

        $this->clock->advance(30);

        $result = $this->consume(Correlation::solicited(self::STATE));

        self::assertSame(ConsumptionStatus::CONSUMED, $result->status);
        self::assertTrue($result->isConsumed());
        self::assertTrue($result->hasRedirectTarget());
        self::assertNull($result->reason);
        self::assertSame($request->id, $result->request?->id);
        self::assertSame('web', $result->application?->name);

        $consumed = $result->consumed;

        self::assertNotNull($consumed);
        self::assertSame(Purpose::SIGN_IN, $consumed->purpose);
        self::assertSame('web', $consumed->application);
        self::assertSame(self::REFERENCE, $consumed->reference->value);
        self::assertSame('2026-11-01T09:30:00+00:00', $consumed->startedAt->toIso8601String());
        self::assertSame('https://idp.example.com', $consumed->expectedIssuer);
        self::assertTrue($consumed->issuerRequired);
        self::assertSame(self::SAML_REQUEST_ID, $consumed->samlRequestId);
        self::assertTrue($consumed->isNonce(self::NONCE));
        self::assertFalse($consumed->isNonce(self::STATE));
        self::assertSame(self::PKCE_VERIFIER, $consumed->codeVerifier()?->reveal());

        self::assertSame('2026-11-01T09:30:30+00:00', $this->reread($request)->consumed_at?->toIso8601String());
        self::assertSame([[RequestConsumption::NAMESPACE, hash('sha256', $request->id), '2026-11-01T09:40:00+00:00']], self::recorded());
        self::assertSame('authorization_request', RequestConsumption::NAMESPACE);

        $this->assertNoEvents();
    }

    /**
     * A request with no PKCE verifier is handed on with none.
     *
     * @return void
     */
    public function testARequestWithNoPkceVerifierIsHandedOnWithNone(): void
    {
        $this->request(['code_verifier' => null, 'nonce_digest' => null]);

        $result = $this->consume(Correlation::solicited(self::STATE));

        self::assertTrue($result->isConsumed());
        self::assertNull($result->consumed?->codeVerifier());
        self::assertFalse((bool) $result->consumed?->isNonce(self::NONCE));
    }

    /**
     * Consumption decrypts nothing; the verifier is decrypted each time it is
     * asked for.
     *
     * @return void
     */
    public function testConsumptionDecryptsNothing(): void
    {
        $encrypter = new CountingSecretEncrypter(app(SecretEncrypter::class));

        $this->app?->instance(SecretEncrypter::class, $encrypter);
        $this->request();

        $consumed = $this->consume(Correlation::solicited(self::STATE))->consumed;

        self::assertNotNull($consumed);
        self::assertSame(0, $encrypter->decryptions);
        self::assertSame(self::PKCE_VERIFIER, $consumed->codeVerifier()?->reveal());
        self::assertSame(1, $encrypter->decryptions);
    }

    /**
     * A verifier no key decrypts still lets the request be consumed; only
     * asking for it fails.
     *
     * @return void
     */
    public function testAVerifierNoKeyDecryptsIsConsumedAndFailsOnlyWhenAskedFor(): void
    {
        $request = $this->request(['code_verifier' => 'not a ciphertext']);
        $result  = $this->consume(Correlation::solicited(self::STATE));

        self::assertTrue($result->isConsumed());
        self::assertNotNull($this->reread($request)->consumed_at);
        self::assertCount(1, self::recorded());

        $this->expectExceptionObject(new DecryptException('The payload is invalid.'));

        $result->consumed?->codeVerifier();
    }

    /**
     * A SAML response finds its request by exact id within its connection,
     * never by `RelayState`.
     *
     * @return void
     */
    public function testASamlRequestIsFoundByItsIdWithinTheConnection(): void
    {
        $request = $this->request(['saml_request_id' => self::SAML_REQUEST_ID]);
        $other   = $this->makeConnection(['enabled' => true]);

        foreach ([[$other, self::SAML_REQUEST_ID], [$this->connection, strtoupper(self::SAML_REQUEST_ID)], [$this->connection, self::SAML_REQUEST_ID . ' ']] as [$route, $id]) {
            self::assertUnknown($this->consume(Correlation::solicited(self::STATE, $id), $route));
        }

        self::assertNull($this->reread($request)->consumed_at);

        $result = $this->consume(Correlation::solicited(self::STATE, self::SAML_REQUEST_ID));

        self::assertTrue($result->isConsumed());
        self::assertSame($request->id, $result->request?->id);
        self::assertSame(self::SAML_REQUEST_ID, $result->consumed?->samlRequestId);
    }

    /**
     * A response naming no known request is unknown, and consumes nothing.
     *
     * @return void
     */
    public function testAResponseThatNamesNoRequestIsUnknown(): void
    {
        $request = $this->request(['saml_request_id' => self::SAML_REQUEST_ID]);

        foreach ([Correlation::solicited('another-state'), Correlation::solicited(null, '_another'), Correlation::unsolicited(), Correlation::uncorrelated()] as $correlation) {
            self::assertUnknown($this->consume($correlation));
        }

        self::assertNull($this->reread($request)->consumed_at);
        self::assertSame([], self::recorded());
    }

    /**
     * A missing or mismatched `RelayState` is `request_mismatch`, and the
     * request is still consumed.
     *
     * @return void
     */
    public function testAMismatchedOrMissingRelayStateIsRefusedAndStillConsumed(): void
    {
        $first  = $this->request(['saml_request_id' => self::SAML_REQUEST_ID]);
        $second = $this->request(['saml_request_id' => '_second-request'], 'second-state');

        $mismatched = $this->consume(Correlation::solicited('second-state', self::SAML_REQUEST_ID));
        $missing    = $this->consume(Correlation::solicited(null, '_second-request'));

        self::assertRefused(FailureReason::REQUEST_MISMATCH, $mismatched, true);
        self::assertRefused(FailureReason::REQUEST_MISMATCH, $missing, true);
        self::assertSame([$first->id, $second->id], [$mismatched->request?->id, $missing->request?->id]);
        self::assertNotNull($this->reread($first)->consumed_at);
        self::assertNotNull($this->reread($second)->consumed_at);
        self::assertReplayed($this->consume(Correlation::solicited(self::STATE, self::SAML_REQUEST_ID)));
    }

    /**
     * A matching `RelayState` is consumed, and an OIDC state alone finds its
     * request.
     *
     * @return void
     */
    public function testAMatchingRelayStateOrAStateAloneIsConsumed(): void
    {
        $this->request(['saml_request_id' => self::SAML_REQUEST_ID]);

        self::assertTrue($this->consume(Correlation::solicited(self::STATE, self::SAML_REQUEST_ID))->isConsumed());

        $this->request(['saml_request_id' => '_second-request'], 'second-state');

        self::assertTrue($this->consume(Correlation::solicited('second-state'))->isConsumed());
    }

    /**
     * A SAML request id for a request that keeps none finds nothing.
     *
     * @return void
     */
    public function testASamlRequestIdForARequestThatKeepsNoneIsUnknown(): void
    {
        $request = $this->request();

        self::assertUnknown($this->consume(Correlation::solicited(self::STATE, self::SAML_REQUEST_ID)));
        self::assertNull($this->reread($request)->consumed_at);
    }

    /**
     * A consumed request is replayed after, with no redirect target and its
     * time unchanged.
     *
     * @return void
     */
    public function testAConsumedRequestIsReplayedAfter(): void
    {
        $request = $this->request();

        self::assertTrue($this->consume(Correlation::solicited(self::STATE))->isConsumed());

        $this->clock->advance(5);

        $replayed = $this->consume(Correlation::solicited(self::STATE));

        self::assertReplayed($replayed);
        self::assertSame($request->id, $replayed->request?->id);
        self::assertSame('2026-11-01T09:30:00+00:00', $this->reread($request)->consumed_at?->toIso8601String());
        self::assertCount(1, self::recorded());
    }

    /**
     * A request already marked consumed is replayed without asking the store.
     *
     * @return void
     */
    public function testARequestMarkedConsumedIsReplayedWithoutRecording(): void
    {
        $this->request(['consumed_at' => $this->clock->now()->subMinute()]);

        self::assertReplayed($this->consume(Correlation::solicited(self::STATE)));
        self::assertSame([], self::recorded());
    }

    /**
     * A request the single-use store has seen is replayed, and not marked.
     *
     * @return void
     */
    public function testARequestTheStoreHasSeenIsReplayed(): void
    {
        $request = $this->request();

        app(SingleUseStore::class)->record(RequestConsumption::NAMESPACE, $request->id, $this->clock->now()->addMinute());

        self::assertReplayed($this->consume(Correlation::solicited(self::STATE)));
        self::assertNull($this->reread($request)->consumed_at);
    }

    /**
     * A voided request is refused `connection_unavailable`, and consumed.
     *
     * @return void
     */
    public function testAVoidedRequestIsRefused(): void
    {
        $request = $this->request(['voided_at' => $this->clock->now()]);

        self::assertRefused(FailureReason::CONNECTION_UNAVAILABLE, $this->consume(Correlation::solicited(self::STATE)), true);
        self::assertNotNull($this->reread($request)->consumed_at);
    }

    /**
     * Rows of `[request's trust version, connection's, reason]`.
     *
     * @return iterable<string, array{0: int, 1: int, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideTrustVersions(): iterable
    {
        yield from [
            'the same'               => [4, 4, null],
            'the connection raised'  => [4, 5, FailureReason::CONNECTION_UNAVAILABLE],
            'the connection lowered' => [4, 3, FailureReason::CONNECTION_UNAVAILABLE],
        ];
    }

    /**
     * A request of another trust version is refused `connection_unavailable`,
     * and consumed.
     *
     * @param  int  $started
     * @param  int  $current
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideTrustVersions')]
    public function testARequestOfAnotherTrustVersionIsRefused(int $started, int $current, ?FailureReason $reason): void
    {
        $request = $this->request(['trust_version' => $started]);

        $this->connection->forceFill(['trust_version' => $current])->save();

        $result = $this->consume(Correlation::solicited(self::STATE), $this->connection->fresh());

        if ($reason === null) {
            self::assertTrue($result->isConsumed());
        } else {
            self::assertRefused($reason, $result, true);
        }

        self::assertNotNull($this->reread($request)->consumed_at);
    }

    /**
     * A request of another connection is refused `connection_mismatch`, and
     * consumed.
     *
     * @return void
     */
    public function testARequestOfAnotherConnectionIsRefused(): void
    {
        $request = $this->request();
        $other   = $this->makeConnection(['enabled' => true]);

        self::assertRefused(FailureReason::CONNECTION_MISMATCH, $this->consume(Correlation::solicited(self::STATE), $other), true);
        self::assertNotNull($this->reread($request)->consumed_at);
    }

    /**
     * Each moment around the 09:40:00 expiry, its reason, and how long the
     * store keeps the request.
     *
     * @return iterable<string, array{0: int, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason, 2: string}>
     */
    public static function expiries(): iterable
    {
        yield 'one second before' => [-1, null, '2026-11-01T09:40:00+00:00'];
        yield 'at the second' => [0, FailureReason::REQUEST_EXPIRED, '2026-11-01T09:40:01+00:00'];
        yield 'one second after' => [1, FailureReason::REQUEST_EXPIRED, '2026-11-01T09:40:02+00:00'];
    }

    /**
     * A request expires at its expiry's second; the store keeps it at least a
     * second.
     *
     * @param  int  $offset
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  string  $recordedUntil
     * @return void
     */
    #[DataProvider('expiries')]
    public function testARequestExpiresAtItsExpirysSecond(int $offset, ?FailureReason $reason, string $recordedUntil): void
    {
        $request = $this->request(['expires_at' => $this->clock->now()->addSeconds(600)]);

        $this->clock->advance(600 + $offset);

        $result = $this->consume(Correlation::solicited(self::STATE));

        if ($reason === null) {
            self::assertTrue($result->isConsumed());
        } else {
            self::assertRefused($reason, $result, true);
        }

        self::assertNotNull($this->reread($request)->consumed_at);
        self::assertSame([[RequestConsumption::NAMESPACE, hash('sha256', $request->id), $recordedUntil]], self::recorded());
    }

    /**
     * A request of an unregistered application is refused first, with no
     * redirect, and completed at once.
     *
     * @return void
     */
    public function testARequestOfAnUnregisteredApplicationHasNoRedirectTarget(): void
    {
        $request = $this->request(['application' => 'retired', 'voided_at' => $this->clock->now(), 'expires_at' => $this->clock->now()]);

        $this->clock->advance(5);

        $result = $this->consume(Correlation::solicited(self::STATE));
        $row    = $this->reread($request);

        self::assertRefused(FailureReason::APPLICATION_NOT_ALLOWED, $result, false);
        self::assertSame($request->id, $result->request?->id);
        self::assertSame('2026-11-01T09:30:05+00:00', $row->consumed_at?->toIso8601String());
        self::assertSame('2026-11-01T09:30:05+00:00', $row->completed_at?->toIso8601String());
        self::assertSame('2026-11-01T09:30:05+00:00', $result->request->completed_at?->toIso8601String());
    }

    /**
     * A registered application's request is consumed but completed only when
     * the completion ends.
     *
     * @return void
     */
    public function testARequestOfARegisteredApplicationIsNotCompletedByItsConsumption(): void
    {
        $consumed = $this->request([], 'state-1');
        $expired  = $this->request(['expires_at' => $this->clock->now()], 'state-2');

        self::assertTrue($this->consume(Correlation::solicited('state-1'))->isConsumed());
        self::assertRefused(FailureReason::REQUEST_EXPIRED, $this->consume(Correlation::solicited('state-2')), true);

        foreach ([$consumed, $expired] as $request) {
            self::assertNotNull($this->reread($request)->consumed_at);
            self::assertNull($this->reread($request)->completed_at);
        }
    }

    /**
     * A malformed application's settings propagate, leaving the request
     * unconsumed and unrecorded.
     *
     * @return void
     */
    public function testAMalformedApplicationLeavesTheRequestUnconsumed(): void
    {
        $request = $this->request();
        $failure = null;

        config()->set('sso.applications.web.delivery', 'post');

        try {
            $this->consume(Correlation::solicited(self::STATE));
        } catch (\InvalidArgumentException $exception) {
            $failure = $exception->getMessage();
        }

        $row = $this->reread($request);

        self::assertSame('`sso.applications.web.delivery` must be `fragment` or `query`.', $failure);
        self::assertNull($row->consumed_at);
        self::assertNull($row->completed_at);
        self::assertSame([], self::recorded());
    }

    /**
     * Reasons are judged in order: `RelayState`, voiding, connection, trust
     * version, expiry.
     *
     * @return void
     */
    public function testTheReasonsAreJudgedInOrder(): void
    {
        $other = $this->makeConnection(['enabled' => true]);
        $now   = $this->clock->now();

        $this->request(['saml_request_id' => self::SAML_REQUEST_ID, 'voided_at' => $now, 'expires_at' => $now], 'state-1');
        $this->request(['voided_at' => $now, 'expires_at' => $now], 'state-2');
        $this->request(['expires_at' => $now, 'trust_version' => 9], 'state-3');
        $this->request(['expires_at' => $now, 'trust_version' => 9], 'state-4');

        self::assertRefused(FailureReason::REQUEST_MISMATCH, $this->consume(Correlation::solicited('state-2', self::SAML_REQUEST_ID)), true);
        self::assertRefused(FailureReason::CONNECTION_UNAVAILABLE, $this->consume(Correlation::solicited('state-2'), $other), true);
        self::assertRefused(FailureReason::CONNECTION_MISMATCH, $this->consume(Correlation::solicited('state-3'), $other), true);
        self::assertRefused(FailureReason::CONNECTION_UNAVAILABLE, $this->consume(Correlation::solicited('state-4')), true);
    }

    /**
     * A consumption inside the caller's transaction is undone with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConsumptionInsideACallersTransactionIsUndoneWithIt(): void
    {
        $request = $this->request();
        $inside  = null;
        $failure = null;

        try {
            DB::connection(StorageConnection::name())->transaction(function () use (&$inside): void {

                $inside = $this->consume(Correlation::solicited(self::STATE));

                throw new \RuntimeException('The caller failed.');
            });
        } catch (\RuntimeException $exception) {
            $failure = $exception->getMessage();
        }

        self::assertSame('The caller failed.', $failure);
        self::assertInstanceOf(ConsumptionResult::class, $inside);
        self::assertTrue($inside->isConsumed());
        self::assertNull($this->reread($request)->consumed_at);
        self::assertSame([], self::recorded());
        self::assertTrue($this->consume(Correlation::solicited(self::STATE))->isConsumed());
    }

    /**
     * No dump shows the PKCE verifier, nonce or state, even one showing every
     * property.
     *
     * @return void
     */
    public function testThePkceVerifierIsNeverInADump(): void
    {
        $this->request();

        $result = $this->consume(Correlation::solicited(self::STATE));

        self::assertSame(self::PKCE_VERIFIER, $result->consumed?->codeVerifier()?->reveal());

        $cloner = new VarCloner;
        $dumped = (string) (new CliDumper)->dump($cloner->cloneVar([$result, $result->consumed]), true);

        $printed = [print_r($result, true), print_r($result->consumed, true)];

        foreach ([$dumped, ...$printed] as $shown) {
            foreach ([self::PKCE_VERIFIER, self::NONCE, self::STATE, (string) base64_decode(substr(Config::string('app.key'), 7), true)] as $secret) {
                self::assertStringNotContainsString($secret, $shown);
            }
        }

        foreach ($printed as $shown) {
            foreach ([hash('sha256', self::STATE), hash('sha256', self::NONCE)] as $digest) {
                self::assertStringNotContainsString($digest, $shown);
            }
        }
    }

    /**
     * Assert the response named no request: `request_unknown`, no request and
     * no redirect target.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\ConsumptionResult  $result
     * @return void
     */
    private static function assertUnknown(ConsumptionResult $result): void
    {
        self::assertSame(ConsumptionStatus::UNKNOWN, $result->status);
        self::assertTrue($result->isUnknown());
        self::assertSame(FailureReason::REQUEST_UNKNOWN, $result->reason);
        self::assertNull($result->request);
        self::assertNull($result->consumed);
        self::assertFalse($result->hasRedirectTarget());
    }

    /**
     * Assert the request was consumed before: `request_unknown`, and no
     * redirect target.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\ConsumptionResult  $result
     * @return void
     */
    private static function assertReplayed(ConsumptionResult $result): void
    {
        self::assertSame(ConsumptionStatus::REPLAYED, $result->status);
        self::assertTrue($result->isReplayed());
        self::assertSame(FailureReason::REQUEST_UNKNOWN, $result->reason);
        self::assertNotNull($result->request);
        self::assertNull($result->consumed);
        self::assertNull($result->application);
        self::assertFalse($result->hasRedirectTarget());
    }

    /**
     * Assert the request was consumed now and refused for the reason,
     * redirecting to `web` or nowhere.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\ConsumptionResult  $result
     * @param  bool  $redirectable
     * @return void
     */
    private static function assertRefused(FailureReason $reason, ConsumptionResult $result, bool $redirectable): void
    {
        self::assertSame(ConsumptionStatus::REFUSED, $result->status, $reason->value);
        self::assertTrue($result->isRefused());
        self::assertSame($reason, $result->reason);
        self::assertNotNull($result->request);
        self::assertNull($result->consumed);
        self::assertSame($redirectable, $result->hasRedirectTarget());
        self::assertSame($redirectable ? 'web' : null, $result->application?->name);
    }

    /**
     * Consume the request the correlation names, for the request's connection
     * unless told otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $route
     * @return \SineMacula\Laravel\Sso\Flows\ConsumptionResult
     */
    private function consume(Correlation $correlation, ?Connection $route = null): ConsumptionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(RequestConsumption::class)->consume($route ?? $this->connection, $correlation);
    }

    /**
     * A `sign_in` request for `web` through the connection with the state,
     * nonce and verifier.
     *
     * @param  array<string, mixed>  $attributes
     * @param  string  $state
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function request(array $attributes = [], string $state = self::STATE): AuthorizationRequest
    {
        $reference = $state === self::STATE ? self::REFERENCE : strtr(base64_encode(substr(hash('sha256', $state, true), 0, 24)), '+/', '-_');

        return $this->makeAuthorizationRequest($this->connection, $attributes + [
            'reference'     => $reference,
            'state_digest'  => hash('sha256', $state),
            'nonce_digest'  => hash('sha256', self::NONCE),
            'code_verifier' => app(SecretEncrypter::class)->encrypt(self::PKCE_VERIFIER),
        ]);
    }

    /**
     * The request as stored now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function reread(AuthorizationRequest $request): AuthorizationRequest
    {
        return AuthorizationRequest::query()->whereKey($request->id)->sole();
    }

    /**
     * Every key the single-use store holds, with its expiry as ISO 8601.
     *
     * @return list<array{0: string, 1: string, 2: string}>
     */
    private static function recorded(): array
    {
        return array_values(DB::table(StorageConnection::table('single_use.table'))->orderBy('id')->get()->map(static fn (object $row): array => [
            (string) $row->namespace, // @phpstan-ignore property.notFound
            (string) $row->key_digest, // @phpstan-ignore property.notFound
            CarbonImmutable::parse((string) $row->expires_at, 'UTC')->toIso8601String(), // @phpstan-ignore property.notFound
        ])->all());
    }
}
