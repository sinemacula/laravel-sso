<?php

declare(strict_types = 1);

namespace Tests\Integration\Completion;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\UnsolicitedReinitiation;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Integration tests racing IdP-initiated re-initiation against replays and
 * trust changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(UnsolicitedReinitiation::class)]
final class ConcurrentReinitiationTest extends TestCase
{
    use UsesConnections;

    /** @var string The application start URL the connection sends the browser to. */
    private const string START_URL = 'https://app.example.com/sso/start';

    /** @var string The id of the assertion the response carries. */
    private const string ASSERTION_ID = '_assertion-reinitiation-raced-1';

    /** @var float Seconds a racer waits for another's signal before it gives up. */
    private const float SIGNAL_SECONDS = 10.0;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The SAML connection the response arrives for. */
    private Connection $connection;

    /** @var string The id of the trusted certificate that signs the response. */
    private string $signingKeyId;

    /** @var \SineMacula\Laravel\Sso\Protocols\CompletionRequest What the browser posts. */
    private CompletionRequest $post;

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Configure IdP-initiated SAML and create a connection that allows it, with
     * its unsolicited response.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(HandoffIssuer::class, new RecordingHandoffIssuer);
        $this->app?->instance(AttemptLimiter::class, new readonly class implements AttemptLimiter {
            /**
             * Allow every attempt.
             *
             * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
             * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
             */
            #[\Override]
            public function attempt(AttemptSubject $subject): AttemptResult
            {
                unset($subject);

                return AttemptResult::allowed();
            }
        });

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.idp_initiated', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'protocol' => 'saml2',
            'enabled'  => true,
            'settings' => Saml2Settings::fromArray([
                'idp_entity_id'           => FakeSamlIdentityProvider::ENTITY_ID,
                'sso_url'                 => FakeSamlIdentityProvider::SSO_URL,
                'idp_initiated'           => true,
                'idp_initiated_start_url' => self::START_URL,
            ])->toArray(),
        ]);

        $this->signingKeyId = $this->trust(self::idp()->certificate());
        $this->trust(Certificates::distinct(7));

        $this->post     = $this->response();
        $this->outcomes = sys_get_temp_dir() . '/saml-reinitiation-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove this test's signals and outcomes.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (isset($this->outcomes) && is_dir($this->outcomes)) {

            foreach (glob($this->outcomes . '/*') ?: [] as $file) {
                @unlink($file);
            }

            @rmdir($this->outcomes);
        }

        parent::tearDown();
    }

    /**
     * Of two posts of one unsolicited response, exactly one is re-initiated.
     *
     * @return void
     */
    public function testExactlyOneOfTwoPostsOfOneResponseIsReinitiated(): void
    {
        $this->requireRacingProcesses();

        $directory = $this->outcomes;
        $poster    = fn (int $process): array => [function () use ($directory, $process): string {
            $this->afterValidation(static function () use ($directory, $process): void {

                touch("{$directory}/validated-{$process}");

                self::await("{$directory}/validated-0");
                self::await("{$directory}/validated-1");
            });

            return self::outcomeOf($this->complete());
        }, false];

        $outcomes = $this->race([$poster(0), $poster(1)]);
        $listed   = implode(', ', $outcomes);
        $refused  = array_filter($outcomes, static fn (string $outcome): bool => $outcome === 'rejected:replayed' || $outcome === 'serialization');

        self::assertCount(1, array_keys($outcomes, 'reinitiated:-', true), $listed);
        self::assertCount(1, $refused, $listed);
        self::assertSame(1, $this->recorded());
    }

    /**
     * A distrust of the signing certificate after validation refuses the
     * re-initiation.
     *
     * @return void
     */
    public function testADistrustAfterValidationRefusesTheReinitiation(): void
    {
        $this->assertRefusedAfter(fn (): bool => $this->hasDistrustedTheSigningCertificate());
    }

    /**
     * A metadata anchor change after validation refuses the re-initiation.
     *
     * @return void
     */
    public function testAMetadataAnchorChangeAfterValidationRefusesTheReinitiation(): void
    {
        $this->assertRefusedAfter(fn (): bool => $this->trust(Certificates::distinct(9), KeyUse::METADATA_SIGNING) !== '');
    }

    /**
     * Trusting an additional certificate after validation leaves the
     * re-initiation to go on.
     *
     * @return void
     */
    public function testAnAdditiveTrustAfterValidationDoesNotRefuse(): void
    {
        $version = $this->trustVersion();
        $pending = $this->afterValidation(fn (): bool => $this->trust(Certificates::distinct(8)) !== '');
        $result  = $this->complete();

        self::assertSame(['reinitiated', null, self::START_URL . '?connection=' . $this->connection->id], [$result->status->value, $result->reason, $result->startUrl]);
        self::assertCount(0, $pending);
        self::assertSame($version, $this->trustVersion());
        self::assertSame(1, $this->recorded());
    }

    /**
     * IdP-initiated sign-in turned off after validation refuses the
     * re-initiation.
     *
     * @return void
     */
    public function testIdpInitiatedSignInTurnedOffAfterValidationRefusesTheReinitiation(): void
    {
        $version = $this->trustVersion();
        $pending = $this->afterValidation(fn (): bool => $this->hasTurnedIdpInitiatedOff());
        $result  = $this->complete();

        self::assertSame(['rejected', FailureReason::UNSOLICITED_NOT_ALLOWED, null], [$result->status->value, $result->reason, $result->startUrl]);
        self::assertCount(0, $pending);
        self::assertSame($version, $this->trustVersion());
        self::assertSame(0, $this->recorded());
    }

    /**
     * A distrust in another process while the re-initiation is held refuses it.
     *
     * @return void
     */
    public function testADistrustInAnotherProcessRefusesTheReinitiation(): void
    {
        $this->assertRacedChangeRefuses(fn (): bool => $this->hasDistrustedTheSigningCertificate(), 'rejected:connection_unavailable', false);
    }

    /**
     * The same race, the distrust inside a transaction that read the connection
     * first.
     *
     * @return void
     */
    public function testADistrustInsideACallersTransactionRefusesTheReinitiation(): void
    {
        $this->assertRacedChangeRefuses(fn (): bool => $this->hasDistrustedTheSigningCertificate(), 'rejected:connection_unavailable', true);
    }

    /**
     * IdP-initiated sign-in turned off in another process refuses the held
     * re-initiation.
     *
     * @return void
     */
    public function testIdpInitiatedSignInTurnedOffInAnotherProcessRefusesTheReinitiation(): void
    {
        $this->assertRacedChangeRefuses(fn (): bool => $this->hasTurnedIdpInitiatedOff(), 'rejected:unsolicited_not_allowed', false);
    }

    /**
     * The same race, the change inside a transaction that read the connection
     * first.
     *
     * @return void
     */
    public function testIdpInitiatedSignInTurnedOffInsideACallersTransactionRefusesTheReinitiation(): void
    {
        $this->assertRacedChangeRefuses(fn (): bool => $this->hasTurnedIdpInitiatedOff(), 'rejected:unsolicited_not_allowed', true);
    }

    /**
     * Run the change after validation and assert the re-initiation was refused.
     *
     * @param  \Closure(): bool  $change
     * @return void
     */
    private function assertRefusedAfter(\Closure $change): void
    {
        $version = $this->trustVersion();
        $pending = $this->afterValidation($change);
        $result  = $this->complete();

        self::assertSame(['rejected', FailureReason::CONNECTION_UNAVAILABLE, null], [$result->status->value, $result->reason, $result->startUrl]);
        self::assertCount(0, $pending);
        self::assertSame($version + 1, $this->trustVersion());
        self::assertSame(0, $this->recorded());
    }

    /**
     * Race the re-initiation against the change and assert the outcome given.
     *
     * @param  \Closure(): bool  $change
     * @param  string  $refused
     * @param  bool  $inTransaction
     * @return void
     */
    private function assertRacedChangeRefuses(\Closure $change, string $refused, bool $inTransaction): void
    {
        $this->requireRacingProcesses();

        $validated = "{$this->outcomes}/validated";
        $changed   = "{$this->outcomes}/changed";

        $outcomes = $this->race([
            [function () use ($validated, $changed): string {
                $this->afterValidation(static function () use ($validated, $changed): void {
                    touch($validated);
                    self::await($changed);
                });

                return self::outcomeOf($this->complete());
            }, false],
            [static function () use ($validated, $changed, $change): string {
                if (!self::isSignalled($validated)) {
                    return 'error: the re-initiation never signalled it validated';
                }

                try {
                    $made = $change();
                } finally {
                    touch($changed);
                }

                return $made ? 'changed' : 'refused';
            }, $inTransaction],
        ]);

        $expected = match (true) {
            $outcomes[0] === 'serialization' => ['serialization', 'changed', 0],
            $outcomes[1] === 'serialization' => ['reinitiated:-', 'serialization', 1],
            default                          => [$refused, 'changed', 0],
        };

        self::assertSame($expected, [...$outcomes, $this->recorded()]);
    }

    /**
     * Run the change just before the re-initiation opens its transaction.
     *
     * @param  \Closure(): mixed  $change
     * @return \ArrayObject<int, \Closure(): mixed>
     */
    private function afterValidation(\Closure $change): \ArrayObject
    {
        $pending = new \ArrayObject([$change]);

        DB::connection(StorageConnection::name())->beforeStartingTransaction(static function () use ($pending): void {

            $next = $pending[0] ?? null;

            if ($next === null) {
                return;
            }

            unset($pending[0]);
            $next();
        });

        return $pending;
    }

    /**
     * Skip where processes cannot share the database.
     *
     * @return void
     */
    private function requireRacingProcesses(): void
    {
        $shared = DB::connection()->getDriverName() !== 'sqlite' && function_exists('pcntl_fork');

        if ($shared) {
            return;
        }

        self::markTestSkipped('Racing processes need a shared database server and pcntl.');
    }

    /**
     * Stop trusting the response's signing certificate; whether it was removed.
     *
     * @return bool
     */
    private function hasDistrustedTheSigningCertificate(): bool
    {
        return app(KeyService::class)->distrustCertificate('tenant-1', $this->connection->id, $this->signingKeyId, Clients::browser())->isSucceeded();
    }

    /**
     * Turn the connection's IdP-initiated sign-in off; whether it was updated.
     *
     * @return bool
     */
    private function hasTurnedIdpInitiatedOff(): bool
    {
        return app(ConnectionService::class)->update('tenant-1', $this->connection->id, ['settings' => ['idp_initiated' => false]], Clients::browser())->isSucceeded();
    }

    /**
     * Trust the certificate on the connection for the use, and answer its id.
     *
     * @param  string  $certificate
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return string
     */
    private function trust(string $certificate, KeyUse $use = KeyUse::IDP_SIGNING): string
    {
        return app(KeyService::class)->trustCertificate('tenant-1', $this->connection->id, $certificate, Clients::browser(), null, $use)->key->id ?? '';
    }

    /**
     * The connection's trust version, read again.
     *
     * @return int
     */
    private function trustVersion(): int
    {
        return Connection::query()->whereKey($this->connection->id)->sole()->trust_version;
    }

    /**
     * How many assertions are recorded against replay.
     *
     * @return int
     */
    private function recorded(): int
    {
        return SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count();
    }

    /**
     * Complete at the connection's assertion consumer service with the post.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(): CompletionResult
    {
        return app(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connection->id, $this->post, Clients::browser());
    }

    /**
     * How the completion ended, and why.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return string
     */
    private static function outcomeOf(CompletionResult $result): string
    {
        return sprintf('%s:%s', $result->status->value, $result->reason->value ?? '-');
    }

    /**
     * A valid unsolicited response from the identity provider.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\CompletionRequest
     */
    private function response(): CompletionRequest
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, app(Clock::class)->now())
            ->with(['assertion_id' => self::ASSERTION_ID])
            ->completionRequest();
    }

    /**
     * Fork a process per racer, start them together and collect their reports
     * in order.
     *
     * @param  list<array{0: \Closure(): string, 1: bool}>  $racers
     * @return list<string>
     */
    private function race(array $racers): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        foreach ($racers as $process => [$work, $inTransaction]) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $start, $work, $inTransaction);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        foreach (array_keys($racers) as $process) {
            $outcomes[] = (string) file_get_contents("{$this->outcomes}/{$process}");
        }

        return $outcomes;
    }

    /**
     * Run the racer's work on its own connection and exit without the parent's
     * shutdown.
     *
     * @param  int  $process
     * @param  float  $start
     * @param  \Closure(): string  $work
     * @param  bool  $inTransaction
     * @return never
     */
    private function runInChild(int $process, float $start, \Closure $work, bool $inTransaction): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $database = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->beginTransaction();
                Connection::query()->whereKey($this->connection->id)->get();
            }

            $wait = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $outcome = $work();

            if ($inTransaction) {
                $database->commit();
            }
        } catch (\Throwable $e) {
            $outcome = self::isSerializationFailure($e) ? 'serialization' : 'error: ' . $e::class . ': ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Wait up to `SIGNAL_SECONDS` for the signal file, and fail when it never
     * appears.
     *
     * @param  string  $signal
     * @return void
     *
     * @throws \RuntimeException
     */
    private static function await(string $signal): void
    {
        if (!self::isSignalled($signal)) {
            throw new \RuntimeException(sprintf('The barrier timed out waiting for [%s].', basename($signal)));
        }
    }

    /**
     * Wait up to `SIGNAL_SECONDS` for the signal file; whether it appeared.
     *
     * @param  string  $signal
     * @return bool
     */
    private static function isSignalled(string $signal): bool
    {
        $deadline = microtime(true) + self::SIGNAL_SECONDS;

        while (!file_exists($signal)) {

            if (microtime(true) > $deadline) {
                return false;
            }

            usleep(1000);
            clearstatcache(true, $signal);
        }

        return true;
    }

    /**
     * Whether the error, or its cause, is a PostgreSQL serialisation failure
     * (SQLSTATE 40001).
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    private static function isSerializationFailure(\Throwable $exception): bool
    {
        for ($error = $exception; $error !== null; $error = $error->getPrevious()) {
            if ($error instanceof QueryException && (string) $error->getCode() === '40001') {
                return DB::connection()->getDriverName() === 'pgsql';
            }
        }

        return false;
    }

    /**
     * The trusted identity provider, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
