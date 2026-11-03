<?php

declare(strict_types = 1);

namespace Tests\Integration\Keys;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\ExpiryNotifier;
use SineMacula\Laravel\Sso\Keys\ExpiryReport;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RaceFlows;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEveryTable;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Races the expiry report against what takes a key away from it, across
 * processes, each with its own database connection, on PostgreSQL and MySQL
 * (SSO-2.6, SSO-11.12): a key's retirement, another key made current, a
 * certificate no longer trusted, and the connection's deletion. The notifier
 * locks the connection and then the key, in the order each of those takes them.
 *
 * Each runs in both orders, with the reporter's claim forced before and after
 * the change. With the claim taken first, the reporter holds no lock while it
 * dispatches, the change goes through during the dispatch, and the marker's
 * statements then touch no row of a key that went: one warning, and no marker.
 * With the change holding the connection's lock, the reporters read the key,
 * wait on that lock, and find under it that the key went or stopped being
 * reportable: no warning, no claim. A change runs plainly and inside its own
 * `REPEATABLE READ` transaction that read first, in which it may fail to
 * serialise on PostgreSQL alone, on the key's row the claim wrote; a report
 * refuses a caller's transaction, and that refusal has its test in
 * `ExpiryReportTest`.
 *
 * What runs at once, with no order forced, is a smoke test and not proof of the
 * lock order, which `ExpiryNotifierTest::testLocksTheConnectionThenTheKey`
 * pins: any error a racer reports fails it, and keys no change touches are
 * warned of. A reporter stopped between the dispatch and the marker, by a
 * statement failing in its own process, is followed by another once the claim
 * has run out, which sends again: a duplicate, never a loss.
 *
 * Skipped on SQLite and without `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExpiryReport::class)]
#[CoversClass(ExpiryNotifier::class)]
#[CoversClass(KeyService::class)]
#[CoversClass(ConnectionLifecycle::class)]
final class ExpiryReporterRacesTest extends TestCase
{
    use RaceFlows, UsesConnections, UsesEveryTable;

    /** @var string The tenant whose connection it is. */
    private const string TENANT = 'tenant-1';

    /** @var string The instant the clock holds. */
    private const string NOW = '2026-11-01T12:00:00Z';

    /** @var string A retiring key of the service provider's own, retired. */
    private const string RETIRE = 'retire';

    /** @var string A current key of the service provider's own, another made current. */
    private const string MAKE_CURRENT = 'make_current';

    /** @var string A trusted certificate, no longer trusted. */
    private const string DISTRUST = 'distrust';

    /** @var string A trusted certificate, its connection deleted. */
    private const string DELETE = 'delete';

    /** @var string The signal the reporter raises while it dispatches, its claim taken. */
    private const string DISPATCHING = 'dispatching';

    /** @var string The signal the change raises once it ended, however it ended. */
    private const string CHANGED = 'changed';

    /** @var int The threshold, in days, a key ending a day from now has reached. */
    private const int THRESHOLD = 1;

    /** @var int How long a claim lasts here, in seconds. */
    private const int CLAIM_SECONDS = 300;

    /** @var int Seconds from now the keys raced for end. */
    private const int ENDS_IN = 86400;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the keys belong to. */
    private Connection $connection;

    /** @var string The public half every key stands on, read before any process forks. */
    private string $publicKey = '';

    /** @var int How many keys have been made, so each has its own fingerprint. */
    private int $keys = 0;

    /** @var bool Whether the tables were made. */
    private bool $created = false;

    /**
     * Skip where processes cannot share the database; bind a fixed clock and a
     * fresh caller; retire a key at once when another is made current; read the
     * public half before any process forks; and create the tables and the
     * connection.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpRace();

        $this->clock = new FixedClock(self::NOW);

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        config()->set('sso.keys.overlap_seconds', 0);
        config()->set('sso.keys.expiry_claim_seconds', self::CLAIM_SECONDS);

        $this->publicKey = (string) MaskedKey::fromCertificate(Certificates::distinct(50))->publicKey;

        $this->createEveryTable();

        $this->created    = true;
        $this->connection = $this->makeConnection(['protocol' => 'saml2']);
    }

    /**
     * Remove what the race used and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->tearDownRace();

        if ($this->created) {
            $this->dropEveryTable();
        }

        parent::tearDown();
    }

    /**
     * Rows of `[the change, whether it runs in its own transaction that read
     * first]`.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideChanges(): iterable
    {
        foreach ([self::RETIRE, self::MAKE_CURRENT, self::DISTRUST, self::DELETE] as $change) {
            yield "{$change}, plainly" => [$change, false];
            yield "{$change}, inside its own transaction that read first" => [$change, true];
        }
    }

    /**
     * The claim taken before the change: the reporter dispatches once, and
     * holds no lock while it does, so the change goes through; the marker then
     * touches no row of a key that went, and is written on one that stands. A
     * reporter coming after the change sends nothing, and neither throws.
     *
     * @param  string  $change
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideChanges')]
    public function testTheChangeDuringTheDispatchOfAClaim(string $change, bool $reads): void
    {
        [$key, $changing] = $this->watched($change);

        $reports = $this->race([
            fn (): array => $this->reporting(function (): void {
                $this->signal(self::DISPATCHING);
                $this->awaitSignal(self::CHANGED);
            }),
            function () use ($changing): string {

                $this->awaitSignal(self::DISPATCHING);

                try {
                    $status = $changing();

                    $this->commitSnapshot();

                    return $status;
                } finally {
                    $this->signal(self::CHANGED);
                }
            },
            function (): array {

                $this->awaitSignal(self::CHANGED);

                return $this->reporting();
            },
        ], null, $this->snapshotsFor([false, $reads, false], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertFalse(self::assertRacerEnded($reports[2], false));
        self::assertSame(1, $reports[0]['result']['sent']);
        self::assertSame(1, $reports[0]['result']['listed']);
        self::assertSame(1, $reports[0]['result']['notices'][ExpiryNotice::NOTIFIED->value] ?? null);
        self::assertSame(0, $reports[2]['result']['sent']);

        if (self::assertRacerEnded($reports[1], $reads)) {
            $this->assertMarked($key);

            return;
        }

        self::assertSame(self::statusOf($change), $reports[1]['result']);

        if ($change !== self::MAKE_CURRENT) {
            self::assertSame(0, ConnectionKey::query()->whereKey($key)->count());

            return;
        }

        $this->assertMarked($key);

        self::assertSame(KeyState::RETIRING, ConnectionKey::query()->whereKey($key)->sole()->state);
    }

    /**
     * The change holding the connection's lock: the reporters read the key,
     * wait on that lock, and find under it that the key went or stopped being
     * reportable. Nothing is sent, listed, claimed or marked, and neither
     * throws.
     *
     * @param  string  $change
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideChanges')]
    public function testTheChangeHoldingTheConnectionBeforeTheClaim(string $change, bool $reads): void
    {
        [$key, $changing] = $this->watched($change);

        $reporter = function (): array {

            $this->awaitSignal(self::HOLDS);

            return $this->reporting();
        };

        $reports = $this->race([
            fn (): string => $this->holdThenCommit($changing),
            $reporter,
            $reporter,
        ], null, $this->snapshotsFor([$reads, false, false], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertSame(self::statusOf($change), $reports[0]['result']);

        foreach ([$reports[1], $reports[2]] as $report) {
            self::assertFalse(self::assertRacerEnded($report, false));
            self::assertSame(0, $report['result']['sent']);
            self::assertSame(0, $report['result']['listed']);
            self::assertSame([], $report['result']['notices']);
        }

        if ($change !== self::MAKE_CURRENT) {
            self::assertSame(0, ConnectionKey::query()->whereKey($key)->count());

            return;
        }

        $stored = ConnectionKey::query()->whereKey($key)->sole();

        self::assertSame(KeyState::RETIRING, $stored->state);
        self::assertNull($stored->expiry_notified_threshold);
        self::assertNull($stored->expiry_notified_at);
        self::assertNull($stored->expiry_claimed_until);
    }

    /**
     * Rows of `[the seconds of the overlap, the seconds on the reporter's clock
     * past the change's, whether the key is warned of]`: reportable to the last
     * second of its overlap, and not from the second it ends.
     *
     * @return iterable<string, array{0: int, 1: int, 2: bool}>
     */
    public static function provideOverlaps(): iterable
    {
        yield 'a second short of the end of its overlap' => [60, 59, true];
        yield 'at the end of its overlap' => [60, 60, false];
        yield 'past the end of its overlap' => [60, 61, false];
    }

    /**
     * A key made retiring while the reporter waits on the connection's lock is
     * judged under that lock by what it is then: past its overlap it is not
     * warned of, though the reporter read it current; within it, it is.
     *
     * @param  int  $overlap
     * @param  int  $reporterAhead
     * @param  bool  $warned
     * @return void
     */
    #[DataProvider('provideOverlaps')]
    public function testAKeyRetiredPastItsOverlapUnderTheLockIsNotWarnedOf(int $overlap, int $reporterAhead, bool $warned): void
    {
        config()->set('sso.keys.overlap_seconds', $overlap);

        [$key, $changing] = $this->watched(self::MAKE_CURRENT);

        $reports = $this->race([
            fn (): string => $this->holdThenCommit($changing),
            function () use ($reporterAhead): array {

                $this->awaitSignal(self::HOLDS);
                $this->clock->advance($reporterAhead);

                return $this->reporting();
            },
        ]);

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertFalse(self::assertRacerEnded($reports[1], false));
        self::assertSame($warned ? 1 : 0, $reports[1]['result']['sent']);
        self::assertSame($warned ? 1 : 0, $reports[1]['result']['listed']);

        $stored = ConnectionKey::query()->whereKey($key)->sole();

        self::assertSame(KeyState::RETIRING, $stored->state);
        self::assertSame($warned ? self::THRESHOLD : null, $stored->expiry_notified_threshold);
        self::assertNull($stored->expiry_claimed_until);
    }

    /**
     * Reporters and changes at once, with no order forced, end with no error
     * from any racer. No key is warned of twice, the connection deleted holds
     * nothing, and each key on the connection no change touches is warned of
     * once and marked, with no claim left. How many of the others were warned
     * of depends on who won. This is a smoke test: a claim retries a deadlock,
     * so it does not prove the order the locks are taken in, which
     * `ExpiryNotifierTest::testLocksTheConnectionThenTheKey` pins.
     *
     * @return void
     */
    public function testReportersAndChangesAtOnceEndWithNoError(): void
    {
        $distrusted = [];

        for ($key = 0; $key < 5; $key++) {
            $distrusted[] = $this->certificate()->id;
        }

        $deleted = $this->makeConnection(['protocol' => 'saml2', 'display_name' => 'Deleted']);

        for ($key = 0; $key < 5; $key++) {
            $this->certificate($deleted);
        }

        $kept     = $this->makeConnection(['protocol' => 'saml2', 'display_name' => 'Kept']);
        $keptKeys = [];

        for ($key = 0; $key < 3; $key++) {
            $keptKeys[] = $this->certificate($kept)->id;
        }

        sort($keptKeys);

        $reporter = fn (): array => $this->reporting();

        $reports = $this->race([
            $reporter,
            $reporter,
            $reporter,
            function () use ($distrusted): int {

                foreach ($distrusted as $key) {
                    app(KeyService::class)->distrustCertificate(self::TENANT, $this->connection->id, $key);
                }

                return count($distrusted);
            },
            static fn (): string => app(ConnectionLifecycle::class)->delete(self::TENANT, $deleted->id)->status->value,
        ]);

        $results = $this->assertRacersSucceeded($reports);

        self::assertCount(5, $results);
        self::assertSame('deleted', $results[4]);
        self::assertSame(0, ConnectionKey::query()->where('connection_id', $deleted->id)->count());
        self::assertSame(0, ConnectionKey::query()->whereIn('id', $distrusted)->count());
        self::assertSame(count($keptKeys), ConnectionKey::query()->count());
        self::assertSame(0, ConnectionKey::query()->whereNotNull('expiry_claimed_until')->count());

        $sent = array_merge(...array_column(array_slice($results, 0, 3), 'keys'));

        self::assertSame($sent, array_values(array_unique($sent)));

        $sentOfKept = array_values(array_intersect($sent, $keptKeys));

        sort($sentOfKept);

        self::assertSame($keptKeys, $sentOfKept);

        foreach ($keptKeys as $key) {
            $this->assertMarked($key);
        }
    }

    /**
     * A reporter stopped between its dispatch and its marker, by that statement
     * failing, has sent a warning it never recorded. Another inside the claim
     * sends nothing, to the last second of it; one from the second the claim
     * ends sends the warning again and records it. A duplicate, never a loss.
     *
     * @return void
     */
    public function testAReporterStoppedAfterItsDispatchIsFollowedOnceTheClaimHasRunOut(): void
    {
        $key = $this->certificate()->id;

        $reports = $this->race([
            function (): array {

                $this->failStatement(self::onTable('update', StorageConnection::table('keys.table')), 2);

                $sent = 0;

                Event::listen(KeyNearingExpiry::class, static function () use (&$sent): void {
                    $sent++;
                });

                try {
                    app(ExpiryReport::class)->report();

                    return ['sent' => $sent, 'stopped' => false];
                } catch (\Throwable $exception) {
                    return ['sent' => $sent, 'stopped' => self::isInjectedFailure($exception)];
                } finally {
                    $this->signal('stopped');
                }
            },
            function () use ($key): array {

                $this->awaitSignal('stopped');
                $this->clock->advance(self::CLAIM_SECONDS - 1);

                try {
                    $report = $this->reporting();

                    return $report + ['marker' => ConnectionKey::query()->whereKey($key)->sole()->expiry_notified_threshold];
                } finally {
                    $this->signal('claimed');
                }
            },
            function (): array {

                $this->awaitSignal('claimed');
                $this->clock->advance(self::CLAIM_SECONDS);

                return $this->reporting();
            },
        ]);

        [$stopped, $claimed, $following] = $this->assertRacersSucceeded($reports);

        self::assertSame(['sent' => 1, 'stopped' => true], $stopped);

        self::assertSame(0, $claimed['sent']);
        self::assertNull($claimed['marker']);
        self::assertSame(1, $claimed['notices'][ExpiryNotice::CLAIMED->value] ?? null);

        self::assertSame(1, $following['sent']);
        self::assertSame(1, $following['notices'][ExpiryNotice::NOTIFIED->value] ?? null);

        $this->assertMarked($key);
    }

    /**
     * Assert the key stands, marked of its threshold, with no claim left.
     *
     * @param  string  $key
     * @return void
     */
    private function assertMarked(string $key): void
    {
        $stored = ConnectionKey::query()->whereKey($key)->sole();

        self::assertSame(self::THRESHOLD, $stored->expiry_notified_threshold);
        self::assertNotNull($stored->expiry_notified_at);
        self::assertNull($stored->expiry_claimed_until);
    }

    /**
     * Run a report, with what runs at each dispatch, and answer what it sent
     * and how it ended.
     *
     * @param  ?\Closure(): void  $dispatching
     * @return array{sent: int, keys: list<string>, listed: int, notices: array<string, int>}
     */
    private function reporting(?\Closure $dispatching = null): array
    {
        $keys = [];

        Event::listen(KeyNearingExpiry::class, static function (KeyNearingExpiry $event) use ($dispatching, &$keys): void {

            $keys[] = $event->keyId;

            if ($dispatching === null) {
                return;
            }

            $dispatching();
        });

        $run = app(ExpiryReport::class)->report();

        return ['sent' => count($keys), 'keys' => $keys, 'listed' => $run->listed, 'notices' => $run->notices];
    }

    /**
     * The key the change takes away, and the change, each made ready in this
     * process.
     *
     * @param  string  $change
     * @return array{0: string, 1: \Closure(): string}
     *
     * @throws \LogicException
     */
    private function watched(string $change): array
    {
        return match ($change) {
            self::RETIRE       => $this->retirement(),
            self::MAKE_CURRENT => $this->promotion(),
            self::DISTRUST     => $this->distrust(),
            self::DELETE       => $this->deletion(),
            default            => throw new \LogicException(sprintf('No change is named [%s].', $change)),
        };
    }

    /**
     * A retiring key, and its retirement.
     *
     * @return array{0: string, 1: \Closure(): string}
     */
    private function retirement(): array
    {
        $key = $this->ownKey(KeyState::RETIRING, self::ENDS_IN, ['retiring_until' => CarbonImmutable::parse(self::NOW)->addWeek()])->id;

        return [$key, fn (): string => app(KeyService::class)->retire(self::TENANT, $this->connection->id, $key)->status->value];
    }

    /**
     * A current key, and another made current in its place, which retires it.
     * The other's validity ends far beyond what is reported.
     *
     * @return array{0: string, 1: \Closure(): string}
     */
    private function promotion(): array
    {
        $key  = $this->ownKey(KeyState::CURRENT, self::ENDS_IN)->id;
        $next = $this->ownKey(KeyState::NEXT, 86400 * 400)->id;

        return [$key, fn (): string => app(KeyService::class)->makeCurrent(self::TENANT, $this->connection->id, $next)->status->value];
    }

    /**
     * A trusted certificate, and its distrust.
     *
     * @return array{0: string, 1: \Closure(): string}
     */
    private function distrust(): array
    {
        $key = $this->certificate()->id;

        return [$key, fn (): string => app(KeyService::class)->distrustCertificate(self::TENANT, $this->connection->id, $key)->status->value];
    }

    /**
     * A trusted certificate, and its connection's deletion.
     *
     * @return array{0: string, 1: \Closure(): string}
     */
    private function deletion(): array
    {
        return [$this->certificate()->id, fn (): string => app(ConnectionLifecycle::class)->delete(self::TENANT, $this->connection->id)->status->value];
    }

    /**
     * What the change reports when it went through.
     *
     * @param  string  $change
     * @return string
     *
     * @throws \LogicException
     */
    private static function statusOf(string $change): string
    {
        return match ($change) {
            self::RETIRE       => 'retired',
            self::MAKE_CURRENT => 'made_current',
            self::DISTRUST     => 'distrusted',
            self::DELETE       => 'deleted',
            default            => throw new \LogicException(sprintf('No change is named [%s].', $change)),
        };
    }

    /**
     * A key of the service provider's own, in the state, whose validity ends
     * the seconds given from now.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  int  $endsIn
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function ownKey(KeyState $state, int $endsIn, array $attributes = []): ConnectionKey
    {
        return $this->key($this->connection, KeyUse::SP_SIGNING, $endsIn, ['state' => $state] + $attributes);
    }

    /**
     * A certificate the connection trusts, whose validity ends a day from now.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function certificate(?Connection $connection = null): ConnectionKey
    {
        return $this->key($connection ?? $this->connection, KeyUse::IDP_SIGNING, self::ENDS_IN);
    }

    /**
     * A key of the use, whose validity ends the seconds given from now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  int  $endsIn
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function key(Connection $connection, KeyUse $use, int $endsIn, array $attributes = []): ConnectionKey
    {
        $key = new ConnectionKey;

        $key->forceFill($attributes + [
            'connection_id' => $connection->id,
            'use'           => $use,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'public_key'    => $this->publicKey,
            'fingerprint'   => hash('sha256', 'key-' . ++$this->keys),
            'not_after'     => CarbonImmutable::parse(self::NOW)->addSeconds($endsIn),
        ])->save();

        return $key;
    }

    /**
     * What a change's snapshot reads.
     *
     * @return \Closure(): void
     */
    private function reads(): \Closure
    {
        return static function (): void {
            Connection::query()->get();
            ConnectionKey::query()->get();
        };
    }
}
