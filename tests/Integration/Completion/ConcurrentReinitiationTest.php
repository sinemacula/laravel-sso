<?php

declare(strict_types = 1);

namespace Tests\Integration\Completion;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
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
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Races IdP-initiated re-initiation (SSO-5.8, SSO-6.6, SSO-2.13): the
 * completion of an unsolicited response is held once its response is validated,
 * outside any transaction, just before it opens the transaction that locks the
 * connection.
 *
 * - Two posts of one unsolicited response, each in a process of its own, both
 *   validated before either locks: exactly one is re-initiated and the other
 *   refused with `replayed`, and the assertion is recorded once. A completion
 *   runs outside any transaction on the storage connection, so each poster runs
 *   plainly.
 * - Distrusting the certificate that signed the response, or changing the
 *   metadata signing anchors, raises the connection's trust version: the
 *   re-initiation, taking the lock, is refused with `connection_unavailable`
 *   and records nothing.
 * - Trusting an additional certificate is additive and leaves the trust version
 *   alone, so the re-initiation goes on.
 * - Turning the connection's IdP-initiated sign-in off leaves the trust version
 *   alone too, yet the re-initiation, taking the lock, finds it off and is
 *   refused with `unsolicited_not_allowed`, recording nothing.
 *
 * In this process the change runs at the hold, so the order is exact on every
 * database. Across processes, on PostgreSQL and MySQL, a change in a process of
 * its own waits for the re-initiation to signal that it validated, and the
 * re-initiation waits for the change to signal it is made; the change runs
 * plainly, and inside a transaction of its own that read first. On PostgreSQL
 * alone a racer may instead fail to serialise (SQLSTATE `40001`), which records
 * nothing. The cross-process races are skipped on SQLite and without `pcntl`.
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
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

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
     * Bind a fixed clock, fresh authentication, a limiter that allows every
     * attempt and the recording issuer, configure SAML, IdP-initiated sign-in
     * and the endpoints, create the tables, a connection that allows
     * IdP-initiated sign-in, its settings stored as the connection service
     * stores them, and trusts the identity provider and another certificate,
     * and its unsolicited response, and make the directory the processes report
     * in.
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

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::singleUseMigration()->up(); // @phpstan-ignore method.notFound

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
     * Remove this test's signals and outcomes, and drop the tables.
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

        self::singleUseMigration()->down(); // @phpstan-ignore method.notFound
        $this->dropDomainsTable();
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * Two posts of one unsolicited response, each validated before either locks
     * the connection: exactly one is re-initiated and the other refused with
     * `replayed` (or, on PostgreSQL only, fails to serialise), and the
     * assertion is recorded once.
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
     * Distrusting the certificate that signed the response once it is validated
     * raises the trust version: the re-initiation is refused under the lock
     * with `connection_unavailable` and records nothing.
     *
     * @return void
     */
    public function testADistrustAfterValidationRefusesTheReinitiation(): void
    {
        $this->assertRefusedAfter(fn (): bool => $this->hasDistrustedTheSigningCertificate());
    }

    /**
     * Trusting a metadata signing anchor once the response is validated is a
     * trust change that raises the trust version: the re-initiation is refused
     * under the lock with `connection_unavailable` and records nothing.
     *
     * @return void
     */
    public function testAMetadataAnchorChangeAfterValidationRefusesTheReinitiation(): void
    {
        $this->assertRefusedAfter(fn (): bool => $this->trust(Certificates::distinct(9), KeyUse::METADATA_SIGNING) !== '');
    }

    /**
     * Trusting an additional identity provider certificate once the response is
     * validated leaves the trust version alone: the re-initiation goes on and
     * records the assertion.
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
     * Turning the connection's IdP-initiated sign-in off once the response is
     * validated leaves the trust version alone, yet the re-initiation is
     * refused under the lock with `unsolicited_not_allowed` and records
     * nothing.
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
     * Across processes, a distrust committed by another process while the
     * re-initiation is held refuses it under the lock.
     *
     * @return void
     */
    public function testADistrustInAnotherProcessRefusesTheReinitiation(): void
    {
        $this->assertRacedChangeRefuses(fn (): bool => $this->hasDistrustedTheSigningCertificate(), 'rejected:connection_unavailable', false);
    }

    /**
     * The same race, the distrust inside a transaction of its own that read the
     * connection before the race began.
     *
     * @return void
     */
    public function testADistrustInsideACallersTransactionRefusesTheReinitiation(): void
    {
        $this->assertRacedChangeRefuses(fn (): bool => $this->hasDistrustedTheSigningCertificate(), 'rejected:connection_unavailable', true);
    }

    /**
     * Across processes, IdP-initiated sign-in turned off by another process
     * while the re-initiation is held refuses it under the lock with
     * `unsolicited_not_allowed`.
     *
     * @return void
     */
    public function testIdpInitiatedSignInTurnedOffInAnotherProcessRefusesTheReinitiation(): void
    {
        $this->assertRacedChangeRefuses(fn (): bool => $this->hasTurnedIdpInitiatedOff(), 'rejected:unsolicited_not_allowed', false);
    }

    /**
     * The same race, IdP-initiated sign-in turned off inside a transaction of
     * its own that read the connection before the race began.
     *
     * @return void
     */
    public function testIdpInitiatedSignInTurnedOffInsideACallersTransactionRefusesTheReinitiation(): void
    {
        $this->assertRacedChangeRefuses(fn (): bool => $this->hasTurnedIdpInitiatedOff(), 'rejected:unsolicited_not_allowed', true);
    }

    /**
     * Run the change once the response is validated, and assert the
     * re-initiation was refused with `connection_unavailable`, recorded
     * nothing, and the trust version was raised once.
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
     * Race the re-initiation against the change in another process, plain or in
     * its own transaction, and assert the re-initiation was refused under the
     * lock as the outcome given, or, on PostgreSQL only, that one of them
     * failed to serialise and the other's outcome stands.
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
     * Run the change once, just before the next transaction on the storage
     * connection starts: the re-initiation's, which it opens only once the
     * response is validated. Answers what is still to run, empty once it ran.
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
     * Stop trusting the certificate that signs the response; whether the key
     * service removed it.
     *
     * @return bool
     */
    private function hasDistrustedTheSigningCertificate(): bool
    {
        return app(KeyService::class)->distrustCertificate('tenant-1', $this->connection->id, $this->signingKeyId)->isSucceeded();
    }

    /**
     * Turn the connection's IdP-initiated sign-in off through the connection
     * service; whether it updated the connection.
     *
     * @return bool
     */
    private function hasTurnedIdpInitiatedOff(): bool
    {
        return app(ConnectionService::class)->update('tenant-1', $this->connection->id, ['settings' => ['idp_initiated' => false]])->isSucceeded();
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
        return app(KeyService::class)->trustCertificate('tenant-1', $this->connection->id, $certificate, null, $use)->key->id ?? '';
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
        return app(CompletionService::class)->assertionConsumerService($this->connection->id, $this->post);
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
     * What the browser posts: a valid unsolicited response from the identity
     * provider.
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
     * Fork a process for each racer, have each start its work at the same
     * moment on a connection of its own, plain or inside a transaction of its
     * own, and collect what each reported, in the racers' order.
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
     * In a forked process: open a connection of its own, wait for its start, do
     * its work, report the outcome, and end without running the parent's
     * shutdown. Racing inside a transaction, the process opens one and reads
     * the connection before the start, and commits after its work.
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
     * Wait for the signal file, for at most `SIGNAL_SECONDS`, and fail loudly
     * when it never appears: the racer then reports an error, so a race whose
     * racers ran one after the other never passes as one that overlapped.
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
     * Wait for the signal file, for at most `SIGNAL_SECONDS`; whether it
     * appeared.
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
     * Whether the error, or one it was thrown for, is PostgreSQL's
     * serialisation failure (SQLSTATE 40001), accepted only there.
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

    /**
     * The shipped migration of the single-use keys.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function singleUseMigration(): Migration
    {
        return require dirname(__DIR__, 3) . self::SINGLE_USE_MIGRATION;
    }
}
