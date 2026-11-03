<?php

declare(strict_types = 1);

namespace Tests\Integration\Failures;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Console\Scheduling\Event as ScheduledEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Console\Scheduling\ScheduleRunCommand;
use Illuminate\Contracts\Queue\Queue;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Queue\Connectors\ConnectorInterface;
use Illuminate\Queue\NullQueue;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Console\RefreshMetadataCommand;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Operations\OperationsSchedule;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Concerns\FlowRoutes;
use Tests\Concerns\UsesUnreliableCache;
use Tests\TestCase;

/**
 * A cache that is down or lies, in three separate questions (SSO-11.6,
 * SSO-11.5):
 *
 * - Every flow, end to end, with a cache that throws and with one that answers
 *   falsely in each direction: the store is never called, and the results are
 *   the same as with a healthy one.
 * - The scheduler, by the real `schedule:run`: on the default settings a stuck
 *   or broken cache stops nothing the package's tasks do, and only the
 *   framework's own pause signal, where it has one, asks the cache, which
 *   `Schedule::withoutInterruptionPolling()` turns off. The cache mutexes are
 *   an opt-in: a stuck one stops only the tasks that opted in, until
 *   `mutex_minutes` has passed or the operator clears the cache.
 * - What an application binds as authoritative is another matter: a single-use
 *   store over Redis, or a queue, is the application's choice of a dependency
 *   with its own guarantees (`docs/guides/single-use-store.md`). A store that
 *   throws refuses the flow with a server error, and one that refuses refuses;
 *   neither ever passes it. A queue that is down fails the command that queues.
 *
 * A scheduled command runs in this process, from its event's `before` callback,
 * and the event's own process is a no-op, since the Testbench skeleton's
 * `artisan` has no package registered: the schedule, its filters and its
 * mutexes are the real ones, and the command is the real one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(CompletionService::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(OperationsSchedule::class)]
#[CoversClass(RefreshMetadataCommand::class)]
final class CacheOutageTest extends TestCase
{
    use FlowRoutes, UsesUnreliableCache;

    /** @var string The tenant of the connections here. */
    private const string TENANT = 'tenant-cache-outage';

    /** @var list<string> Every task of the schedule, in the order it registers them. */
    private const array EVERY_TASK = ['sso:prune', 'sso:domains:recheck', 'sso:metadata:refresh', 'sso:keys:expiring'];

    /** @var list<string> The commands the schedule ran, in order. */
    private array $ran = [];

    /** @var array<string, int> The exit code of each command the schedule ran. */
    private array $exitCodes = [];

    /** @var ?string The directory a mutex test keeps its cache in. */
    private ?string $mutexDirectory = null;

    /** @var bool Whether the store a test bound has lost its server. */
    private bool $storeDown = false;

    /**
     * Create the tables and the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->prepareFlows();
        $this->createEveryTable();
        $this->registerFlowRoutes();
    }

    /**
     * Restore Laravel's clock and the schedule's polling, remove the mutex
     * cache, and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        self::restoreInterruptionPolling();

        if ($this->mutexDirectory !== null) {
            (new Filesystem)->deleteDirectory($this->mutexDirectory);
        }

        $this->dropEveryTable();

        parent::tearDown();
    }

    /**
     * Rows of `[broken, answer, locks free]`: a cache that is down, one that
     * loses everything, and one that answers what it was never told, each lock
     * free or stuck.
     *
     * @return iterable<string, array{0: bool, 1: mixed, 2: bool}>
     */
    public static function provideUnreliableCaches(): iterable
    {
        yield 'down' => [true, null, true];
        yield 'losing everything, its locks free' => [false, null, true];
        yield 'losing everything, its locks stuck' => [false, null, false];
        yield 'answering true, its locks stuck' => [false, true, false];
        yield 'answering a stale value, its locks free' => [false, 'a stale value', true];
    }

    /**
     * Every flow comes to the same result with the cache healthy and with it
     * down or lying, and the store is never called.
     *
     * @param  bool  $broken
     * @param  mixed  $answer
     * @param  bool  $locksFree
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideUnreliableCaches')]
    public function testEveryFlowRunsAlikeWhateverTheCacheSays(bool $broken, mixed $answer, bool $locksFree): void
    {
        $healthy = $this->everyFlow('healthy');
        $store   = $broken ? $this->breakTheCache() : $this->makeTheCacheLie($answer, $locksFree);

        self::assertSame($healthy, $this->everyFlow('unreliable'));
        self::assertSame(0, $store->calls);
    }

    /**
     * The rate limits count in the database, whatever the cache says.
     *
     * @param  bool  $broken
     * @param  mixed  $answer
     * @param  bool  $locksFree
     * @return void
     */
    #[DataProvider('provideUnreliableCaches')]
    public function testARateLimitCountsWhateverTheCacheSays(bool $broken, mixed $answer, bool $locksFree): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-outage-limits', self::flowKey('outage'));
        $store      = $broken ? $this->breakTheCache() : $this->makeTheCacheLie($answer, $locksFree);

        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $this->flowStart($connection)->assertOk();
        $this->flowStart($connection)->assertStatus(429);

        self::assertSame(0, $store->calls);
    }

    /**
     * With the schedule's polling off, `schedule:run` on the default settings
     * touches no cache at all: down or lying, every command runs and passes,
     * and the store is never called.
     *
     * @param  bool  $broken
     * @param  mixed  $answer
     * @param  bool  $locksFree
     * @return void
     *
     * @throws \Symfony\Component\Console\Exception\ExceptionInterface
     */
    #[DataProvider('provideUnreliableCaches')]
    public function testAScheduleWithoutPollingTouchesNoCache(bool $broken, mixed $answer, bool $locksFree): void
    {
        if (!(new \ReflectionClass(Schedule::class))->hasMethod('withoutInterruptionPolling')) {
            self::markTestSkipped('This Laravel has no polling to turn off.');
        }

        Schedule::withoutInterruptionPolling();

        $store = $broken ? $this->breakTheCache() : $this->makeTheCacheLie($answer, $locksFree);

        $this->travelToMidnight();
        $this->runSchedule($this->schedule());

        self::assertSame(self::EVERY_TASK, $this->ran);
        self::assertSame(array_fill_keys(self::EVERY_TASK, 0), $this->exitCodes);
        self::assertSame(0, $store->calls);
    }

    /**
     * With the framework's own polling left as it is, `schedule:run` stops for
     * its pause signal alone, as `operations.md` says of a framework that has
     * one: the cache down stops it before any task, one answering anything
     * truthy reads as paused, and one that answers nothing runs every command,
     * its locks free or stuck. A framework with no signal runs every command.
     *
     * @param  bool  $broken
     * @param  mixed  $answer
     * @param  bool  $locksFree
     * @return void
     *
     * @throws \Symfony\Component\Console\Exception\ExceptionInterface
     */
    #[DataProvider('provideUnreliableCaches')]
    public function testScheduleRunStopsForThePauseSignalAlone(bool $broken, mixed $answer, bool $locksFree): void
    {
        $polls = (new \ReflectionClass(Schedule::class))->hasProperty('pausable');

        if ($broken) {
            $this->breakTheCache();
        } else {
            $this->makeTheCacheLie($answer, $locksFree);
        }

        $this->travelToMidnight();

        if ($broken && $polls) {
            $this->expectException(\RuntimeException::class);
            $this->expectExceptionMessage('The cache is down.');
        }

        $this->runSchedule($this->schedule());

        $ran = $polls && $answer !== null ? [] : self::EVERY_TASK;

        self::assertSame($ran, $this->ran);
        self::assertSame(array_fill_keys($ran, 0), $this->exitCodes);
    }

    /**
     * A mutex a dead process left stops nothing on the default settings.
     *
     * @return void
     *
     * @throws \Symfony\Component\Console\Exception\ExceptionInterface
     */
    public function testAStuckMutexStopsNothingOnTheDefaultSettings(): void
    {
        $this->useAMutexCache();
        $this->travelToMidnight();
        $this->holdTheMutexOf('sso:prune');

        $this->runSchedule($this->schedule());

        self::assertSame(self::EVERY_TASK, $this->ran);
    }

    /**
     * With the opt-in, a mutex a dead process left stops the task that holds it
     * and no other.
     *
     * @return void
     *
     * @throws \Symfony\Component\Console\Exception\ExceptionInterface
     */
    public function testAStuckMutexStopsOnlyThatTask(): void
    {
        config()->set('sso.operations.cache_mutexes', true);

        $this->useAMutexCache();
        $this->travelToMidnight();
        $this->holdTheMutexOf('sso:prune');

        $this->runSchedule($this->schedule());

        self::assertSame(['sso:domains:recheck', 'sso:metadata:refresh', 'sso:keys:expiring'], $this->ran);
    }

    /**
     * With the opt-in, a stuck mutex holds for exactly `mutex_minutes`: the
     * task is stopped a minute short of it and runs once it has passed.
     *
     * @return void
     *
     * @throws \Symfony\Component\Console\Exception\ExceptionInterface
     */
    public function testAStuckMutexRecoversOnceItsMinutesHavePassed(): void
    {
        config()->set('sso.operations.cache_mutexes', true);
        config()->set('sso.operations.mutex_minutes', 15);
        config()->set('sso.operations.cadence.prune', '* * * * *');

        $this->useAMutexCache();
        $this->travelToMidnight();
        $this->holdTheMutexOf('sso:prune');

        $this->travelTo(CarbonImmutable::parse('2026-11-02T00:14:00Z'));
        $this->runSchedule($this->schedule());

        self::assertNotContains('sso:prune', $this->ran);

        $this->travelTo(CarbonImmutable::parse('2026-11-02T00:15:00Z'));
        $this->runSchedule($this->schedule());

        self::assertContains('sso:prune', $this->ran);
    }

    /**
     * With the opt-in, clearing the mutexes frees a stuck task at once.
     *
     * @return void
     *
     * @throws \Symfony\Component\Console\Exception\ExceptionInterface
     */
    public function testAStuckMutexRecoversOnceTheCacheIsCleared(): void
    {
        config()->set('sso.operations.cache_mutexes', true);

        $this->useAMutexCache();
        $this->travelToMidnight();
        $this->holdTheMutexOf('sso:prune');

        $this->app?->instance(Schedule::class, $this->schedule());

        self::assertSame(0, Artisan::call('schedule:clear-cache'));

        $this->runSchedule($this->schedule());

        self::assertContains('sso:prune', $this->ran);
    }

    /**
     * With the opt-in, a cache whose locks are never free stops every task: a
     * cost the application chose, which the default never has.
     *
     * @return void
     *
     * @throws \Symfony\Component\Console\Exception\ExceptionInterface
     */
    public function testACacheWhoseLocksAreStuckStopsWhatOptedIn(): void
    {
        $this->makeTheCacheLie(null, false);
        $this->travelToMidnight();

        config()->set('sso.operations.cache_mutexes', true);

        $this->runSchedule($this->schedule());

        self::assertSame([], $this->ran);

        config()->set('sso.operations.cache_mutexes', false);

        $this->runSchedule($this->schedule());

        self::assertSame(self::EVERY_TASK, $this->ran);
    }

    /**
     * A bound store that throws at the consumption refuses the flow with a
     * server error: the request is unconsumed, no code is issued, and with the
     * store back the same answer completes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAStoreThatThrowsRefusesTheCompletionWithAServerError(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-outage-store', self::flowKey('outage'));
        $start      = $this->startedFlow($connection);
        $grant      = $this->flowGrant($connection, $start);

        $this->storeDown = true;

        $this->bindStore(fn (): bool => $this->storeDown, static fn (): ?SingleUseOutcome => null);

        $this->deliverGrant($connection, $grant)->assertServerError();

        self::assertNull(AuthorizationRequest::query()->useWritePdo()->where('reference', $start['reference'])->sole()->consumed_at);
        self::assertSame(0, HandoffCode::query()->useWritePdo()->count());

        $this->storeDown = false;

        $this->completedCode($this->deliverGrant($connection, $grant));
    }

    /**
     * A bound store that throws at the redemption refuses it with a server
     * error: the code is unspent, and with the store back it redeems.
     *
     * @return void
     */
    public function testAStoreThatThrowsRefusesTheRedemptionWithAServerError(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-outage-store', self::flowKey('outage'));
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start));

        $this->storeDown = true;

        $this->bindStore(fn (): bool => $this->storeDown, static fn (): ?SingleUseOutcome => null);

        $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertServerError();

        self::assertNull(HandoffCode::query()->useWritePdo()->where('request_reference', $start['reference'])->sole()->redeemed_at);

        $this->storeDown = false;

        $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk();
    }

    /**
     * A bound store that throws recording an assertion refuses it with a server
     * error, never as a pass, with no code issued.
     *
     * @return void
     */
    public function testAStoreThatThrowsRefusesAnAssertionWithAServerError(): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-outage');
        $start      = $this->startedFlow($connection);
        $records    = 0;

        // The request's own record goes through, and the assertion's does not.
        $this->bindStore(static function () use (&$records): bool {
            $records++;

            return $records > 1;
        }, static fn (): ?SingleUseOutcome => null);

        $this->completeFlow($connection, $start)->assertServerError();

        self::assertSame(2, $records);
        self::assertSame(0, HandoffCode::query()->useWritePdo()->count());
    }

    /**
     * A bound store that answers `seen` refuses: it never passes a flow, even
     * when it is wrong.
     *
     * @return void
     */
    public function testAStoreThatAnswersSeenRefuses(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-outage-store', self::flowKey('outage'));
        $start      = $this->startedFlow($connection);

        $this->bindStore(static fn (): bool => false, static fn (): SingleUseOutcome => SingleUseOutcome::SEEN);

        $this->completeFlow($connection, $start)->assertStatus(400);

        self::assertSame(0, HandoffCode::query()->useWritePdo()->count());
    }

    /**
     * A store an application builds over its cache is a dependency it chose: it
     * alone reaches the cache, through it a flow completes and a replay is
     * refused, and with that cache down the flow is a server error rather than
     * a pass.
     *
     * @return void
     */
    public function testAStoreOverTheCacheIsAnAuthoritativeDependency(): void
    {
        $this->app?->bind(SingleUseStore::class, static fn (): SingleUseStore => new class implements SingleUseStore {
            /**
             * Record the key in the application's cache.
             *
             * @param  string  $namespace
             * @param  string  $key
             * @param  \Carbon\CarbonImmutable  $until
             * @return \SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome
             */
            #[\Override]
            public function record(string $namespace, #[\SensitiveParameter] string $key, CarbonImmutable $until): SingleUseOutcome
            {
                unset($until);

                return Cache::add($namespace . ':' . hash('sha256', $key), true, 3600) ? SingleUseOutcome::RECORDED : SingleUseOutcome::SEEN;
            }
        });

        $connection = $this->flowOidcConnection(self::TENANT, 'op-outage-store', self::flowKey('outage'));
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start));

        $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk();

        $store = $this->breakTheCache();
        $start = $this->startedFlow($connection);

        self::assertSame(0, $store->calls);

        $this->completeFlow($connection, $start)->assertServerError();

        self::assertSame(1, $store->calls);
        self::assertSame(1, HandoffCode::query()->useWritePdo()->count());
    }

    /**
     * A queue that is down fails the command that queues on it, by the class of
     * what it threw, and leaves the connection due. A flow never needs it.
     *
     * @return void
     */
    public function testAQueueThatIsDownFailsTheCommandAndNoFlow(): void
    {
        $queue = self::queueThatIsDown();

        app('queue')->extend('sso_down', static fn (): ConnectorInterface => new readonly class ($queue) implements ConnectorInterface {
            /**
             * Constructor.
             *
             * @param  \Illuminate\Contracts\Queue\Queue  $queue
             */
            public function __construct(

                /** The queue every connection reaches. */
                private Queue $queue,
            ) {}

            /**
             * The queue that refuses every job.
             *
             * @param  array<mixed>  $config
             * @return \Illuminate\Contracts\Queue\Queue
             */
            #[\Override]
            public function connect(array $config): Queue
            {
                unset($config);

                return $this->queue;
            }
        });

        config()->set('queue.connections.sso_down', ['driver' => 'sso_down']);
        config()->set('sso.features.metadata_refresh', true);
        config()->set('sso.metadata.queue', ['connection' => 'sso_down', 'name' => null, 'timeout_seconds' => 30, 'tries' => 1]);

        $due = $this->makeConnection([
            'tenant_id' => self::TENANT,
            'enabled'   => true,
            'settings'  => ['issuer' => 'https://op-outage-due.example.test', 'metadata_refresh' => true],
        ]);

        self::assertSame(1, Artisan::call('sso:metadata:refresh'));
        self::assertStringContainsString('The metadata refresh stopped on RuntimeException.', Artisan::output());
        self::assertSame([$due->id], app(MetadataRefresher::class)->dueConnectionIds());

        $after = $due->fresh();

        self::assertNotNull($after);
        self::assertSame(0, $after->metadata_version);
        self::assertNull($after->metadata_refresh_at);
        self::assertNull($after->metadata_claimed_until);
        self::assertNull($after->metadata_claim_token);

        self::assertSame(self::TENANT, $this->signedIn($this->flowOidcConnection(self::TENANT, 'op-outage-queue', self::flowKey('outage')))['tenant']);
    }

    /**
     * Every flow, end to end, as a list of what each came to, with nothing in
     * it of a run's own connections.
     *
     * @param  string  $run
     * @return array<string, mixed>
     *
     * @throws \Random\RandomException
     */
    private function everyFlow(string $run): array
    {
        $saml     = $this->flowSamlConnection(self::TENANT, 'idp-outage', ['idp_initiated' => true, 'idp_initiated_start_url' => self::FLOW_START_URL]);
        $oidc     = $this->flowOidcConnection(self::TENANT, "op-outage-{$run}", self::flowKey('outage'));
        $identity = new IdentityReference('App\Models\User', 'person-outage');

        $this->flowVerifiedDomain($oidc, "{$run}.example.com");

        $renewals = $this->flowSessions->renewals();
        $linkId   = $this->linkedThroughFlow($oidc, $identity);
        $signedIn = $this->signedIn($oidc);
        $renewed  = $this->reauthenticatedThroughFlow($oidc, $identity, $linkId);

        return [
            'saml'           => self::outcomeOf($this->signedIn($saml)),
            'oidc'           => self::outcomeOf($signedIn),
            'linked'         => $signedIn['link_id'] === $linkId,
            'reauthenticate' => self::outcomeOf($renewed),
            'renewals'       => $this->flowSessions->renewals() - $renewals,
            'replay'         => $this->replayedCode($saml),
            'answered_twice' => $this->answeredTwice($oidc),
            'refused'        => $this->refusedResponse($saml),
            'discovery'      => $this->discovered($oidc, "person@{$run}.example.com"),
            'no_discovery'   => $this->sendFlowRequest('POST', '/sso/discover', ['email' => 'person@nowhere.example.com'])->json('navigation.url'),
            'reinitiated'    => str_replace($saml->id, '{id}', $this->reinitiatedTo($saml)),
            'metadata'       => $this->sendFlowRequest('GET', '/sso/metadata/' . self::TENANT . "/{$saml->id}")->baseResponse->getStatusCode(),
            'jwks'           => $this->publicKeysServed($run),
        ];
    }

    /**
     * What a redemption came to, without what differs from run to run.
     *
     * @param  array<string, mixed>  $answer
     * @return array<string, mixed>
     */
    private static function outcomeOf(array $answer): array
    {
        return array_intersect_key($answer, array_flip(['status', 'reason', 'subject', 'tenant', 'linked']));
    }

    /**
     * Why a second redemption of one code is refused.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return mixed
     */
    private function replayedCode(Connection $connection): mixed
    {
        $start = $this->startedFlow($connection);
        $code  = $this->completedCode($this->completeFlow($connection, $start));

        $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk();

        return $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->json('reason');
    }

    /**
     * The status of a second answer for one request.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return int
     *
     * @throws \Random\RandomException
     */
    private function answeredTwice(Connection $connection): int
    {
        $grant = $this->flowGrant($connection, $this->startedFlow($connection));

        $this->completedCode($this->deliverGrant($connection, $grant));

        return $this->deliverGrant($connection, $grant)->baseResponse->getStatusCode();
    }

    /**
     * The error a response no certificate signed comes to.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return string
     */
    private function refusedResponse(Connection $connection): string
    {
        $tailor = static fn (FakeSamlResponse $response): FakeSamlResponse => $response->signed(false, false);
        $answer = $this->completeFlow($connection, $this->startedFlow($connection), $tailor);

        $this->assertFailedFlow($answer, FailureReason::SIGNATURE_INVALID);

        return self::flowText(self::flowRedirect($answer)['error'] ?? null);
    }

    /**
     * Whether discovery sends the email to the connection's provider.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $email
     * @return bool
     */
    private function discovered(Connection $connection, string $email): bool
    {
        $url = self::flowText($this->sendFlowRequest('POST', '/sso/discover', ['email' => $email])->json('navigation.url'));

        return str_starts_with($url, $this->flowProvider($connection)->endpoint('authorization'));
    }

    /**
     * Where an unsolicited response at the connection leads the browser.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return string
     */
    private function reinitiatedTo(Connection $connection): string
    {
        return (string) $this->postSamlResponse($connection, $this->flowSamlResponse($connection))->baseResponse->headers->get('Location');
    }

    /**
     * How many public keys a connection with one serves.
     *
     * @param  string  $run
     * @return int
     */
    private function publicKeysServed(string $run): int
    {
        $connection = $this->flowOidcConnection(self::TENANT, "op-outage-keys-{$run}", self::flowKey('outage'), settings: ['client_authentication' => 'private_key_jwt']);

        app(KeyService::class)->addNext(self::TENANT, $connection->id, KeyUse::CLIENT_ASSERTION, KeyType::EC);

        return count((array) $this->sendFlowRequest('GET', "/sso/jwks/{$connection->id}")->assertOk()->json('keys'));
    }

    /**
     * Bind a single-use store over the database one, that throws while `down`
     * answers true, and answers what `answer` gives when it gives anything.
     *
     * @param  \Closure(): bool  $down
     * @param  \Closure(): ?\SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome  $answer
     * @return void
     */
    private function bindStore(\Closure $down, \Closure $answer): void
    {
        $this->app?->bind(SingleUseStore::class, static fn (): SingleUseStore => new readonly class ($down, $answer, app(DatabaseSingleUseStore::class)) implements SingleUseStore {
            /**
             * Constructor.
             *
             * @param  \Closure(): bool  $down
             * @param  \Closure(): ?\SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome  $answer
             * @param  \SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore  $store
             */
            public function __construct(

                /** Whether its server has gone. */
                private \Closure $down,

                /** What it answers, whatever is asked. */
                private \Closure $answer,

                /** What records it, when it is up and has no answer of its own. */
                private DatabaseSingleUseStore $store,
            ) {}

            /**
             * Fail, or answer, or record.
             *
             * @param  string  $namespace
             * @param  string  $key
             * @param  \Carbon\CarbonImmutable  $until
             * @return \SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function record(string $namespace, #[\SensitiveParameter] string $key, CarbonImmutable $until): SingleUseOutcome
            {
                if (($this->down)()) {
                    throw new \RuntimeException('The store is down.');
                }

                return ($this->answer)() ?? $this->store->record($namespace, $key, $until);
            }
        });
    }

    /**
     * Keep the mutexes in a cache of files, whose locks run out by the time
     * Laravel's clock reads, as a shared store's do.
     *
     * @return void
     */
    private function useAMutexCache(): void
    {
        $this->mutexDirectory = sys_get_temp_dir() . '/sso-mutexes-' . Str::lower((string) Str::ulid());

        config()->set('cache.stores.sso_mutexes', ['driver' => 'file', 'path' => $this->mutexDirectory]);
        config()->set('cache.default', 'sso_mutexes');
    }

    /**
     * Hold the task's mutex, as a process that died running it leaves it.
     *
     * @param  string  $task
     * @return void
     */
    private function holdTheMutexOf(string $task): void
    {
        $was = config('sso.operations.cache_mutexes');

        config()->set('sso.operations.cache_mutexes', true);

        foreach ($this->schedule()->events() as $event) {

            if (self::taskOf($event) !== $task) {
                continue;
            }

            self::assertTrue($event->mutex->create($event));
        }

        config()->set('sso.operations.cache_mutexes', $was);
    }

    /**
     * Set Laravel's clock to midnight, when every default cadence is due.
     *
     * @return void
     */
    private function travelToMidnight(): void
    {
        $this->travelTo(CarbonImmutable::parse('2026-11-02T00:00:00Z'));
    }

    /**
     * A schedule as an application's holds it, each event running its real
     * command here when it starts, and a no-op as its own process. The no-op
     * names the task, since an event's mutex is named from its command.
     *
     * @return \Illuminate\Console\Scheduling\Schedule
     */
    private function schedule(): Schedule
    {
        $schedule = new Schedule;

        app(OperationsSchedule::class)->register($schedule);

        foreach ($schedule->events() as $event) {

            $task = self::taskOf($event);

            $event->command = "true {$task}";

            $event->before(function () use ($task): void {
                $this->ran[]            = $task;
                $this->exitCodes[$task] = Artisan::call($task);
            });
        }

        return $schedule;
    }

    /**
     * The task the event runs.
     *
     * @param  \Illuminate\Console\Scheduling\Event  $event
     * @return string
     */
    private static function taskOf(ScheduledEvent $event): string
    {
        self::assertSame(1, preg_match('/sso:[a-z:]+/', (string) $event->command, $matches));

        return $matches[0];
    }

    /**
     * Run the real `schedule:run`, a new command each time, as a new process
     * is, over the schedule.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     *
     * @throws \Symfony\Component\Console\Exception\ExceptionInterface
     */
    private function runSchedule(Schedule $schedule): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $this->ran       = [];
        $this->exitCodes = [];

        $app->instance(Schedule::class, $schedule);

        $command = new ScheduleRunCommand;

        $command->setLaravel($app);

        $command->run(new ArrayInput([]), new BufferedOutput);
    }

    /**
     * A queue that refuses every job, as a client whose server has gone does.
     *
     * @return \Illuminate\Contracts\Queue\Queue
     */
    private static function queueThatIsDown(): Queue
    {
        return new class extends NullQueue {
            /**
             * Refuse the job.
             *
             * @param  mixed  $job
             * @param  mixed  $data
             * @param  mixed  $queue
             * @return never
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function push(mixed $job, mixed $data = '', mixed $queue = null): never
            {
                unset($job, $data, $queue);

                throw new \RuntimeException('The queue is down.');
            }
        };
    }

    /**
     * Turn the schedule's polling back on, as the framework leaves it, so no
     * test leaks into the next.
     *
     * @return void
     */
    private static function restoreInterruptionPolling(): void
    {
        $schedule = new \ReflectionClass(Schedule::class);

        foreach (['pausable', 'interruptible'] as $property) {

            if (!$schedule->hasProperty($property)) {
                continue;
            }

            $schedule->setStaticPropertyValue($property, true);
        }
    }
}
