<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\ExpiryClaim;
use SineMacula\Laravel\Sso\Keys\ExpiryNotifier;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\FailsDatabaseStatements;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\RecordsLockOrder;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for sending one key's expiry warning at least once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExpiryNotifier::class)]
#[CoversClass(ExpiryClaim::class)]
final class ExpiryNotifierTest extends TestCase
{
    use CapturesLogs, FailsDatabaseStatements, RecordsEventSequences, RecordsLockOrder, UsesConnections;

    /** @var string The instant the clock holds. */
    private const string NOW = '2026-11-01T12:00:00Z';

    /** @var int The seconds in a day. */
    private const int DAY = 86400;

    /** @var int How many keys have been made, so each has its own fingerprint. */
    private int $keys = 0;

    /** @var \Tests\Fixtures\FixedClock The clock the notifier reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A connection. */
    private Connection $connection;

    /**
     * Bind a fixed clock, create the tables and a connection, and record events
     * and logs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock(self::NOW);

        $this->app?->instance(Clock::class, $this->clock);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2']);

        $this->captureLogs();
        $this->startRecordingEvents();
    }

    /**
     * The claim locks the connection then the key in one transaction, and the
     * marker is written only after the dispatch.
     *
     * @return void
     */
    public function testTheMarkerIsWrittenOnlyAfterTheDispatch(): void
    {
        $key  = $this->key(self::DAY);
        $seen = null;

        Event::listen(KeyNearingExpiry::class, static function () use ($key, &$seen): void {
            $seen = ConnectionKey::query()->whereKey($key->id)->sole();
        });

        self::assertSame(ExpiryNotice::NOTIFIED, $this->notifier()->notify($key, Clients::browser()));

        self::assertInstanceOf(ConnectionKey::class, $seen);
        self::assertNull($seen->expiry_notified_threshold);
        self::assertNull($seen->expiry_notified_at);
        self::assertSame('2026-11-01T12:05:00Z', $seen->expiry_claimed_until?->format('Y-m-d\TH:i:s\Z'));

        $stored = ConnectionKey::query()->whereKey($key->id)->sole();

        self::assertSame(1, $stored->expiry_notified_threshold);
        self::assertSame(self::NOW, $stored->expiry_notified_at?->format('Y-m-d\TH:i:s\Z'));
        self::assertNull($stored->expiry_claimed_until);
    }

    /**
     * The connection is locked before the key.
     *
     * @return void
     */
    public function testLocksTheConnectionThenTheKey(): void
    {
        $key        = $this->key(self::DAY);
        $statements = [];

        $this->recordLockOrder();

        DB::connection()->listen(static function ($query) use (&$statements): void {
            $statements[] = strtolower($query->sql);
        });

        $this->notifier()->notify($key, Clients::browser());

        $locks = array_values(array_filter($statements, static fn (string $sql): bool => str_contains($sql, 'for update')));

        self::assertCount(2, $locks);
        self::assertStringContainsString('sso_connections', $locks[0]);
        self::assertStringContainsString('sso_keys', $locks[1]);
    }

    /**
     * How long a claim lasts is the setting's.
     *
     * @return void
     */
    public function testAClaimLastsAsConfigured(): void
    {
        config()->set('sso.keys.expiry_claim_seconds', 60);

        $key  = $this->key(self::DAY);
        $seen = null;

        Event::listen(KeyNearingExpiry::class, static function () use ($key, &$seen): void {
            $seen = ConnectionKey::query()->whereKey($key->id)->sole()->expiry_claimed_until;
        });

        $this->notifier()->notify($key, Clients::browser());

        self::assertSame('2026-11-01T12:01:00Z', $seen?->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * A dispatch that throws records nothing and releases the claim, so a later
     * run sends again; the failure is logged by class alone.
     *
     * @return void
     */
    public function testADispatchThatThrowsRecordsNothingAndIsSentAgain(): void
    {
        $key   = $this->key(self::DAY);
        $calls = 0;

        Event::listen(KeyNearingExpiry::class, static function () use (&$calls): void {
            if (++$calls === 1) {
                throw new \RuntimeException('a secret the listener held');
            }
        });

        self::assertSame(ExpiryNotice::FAILED, $this->notifier()->notify($key, Clients::browser()));

        $stored = ConnectionKey::query()->whereKey($key->id)->sole();

        self::assertNull($stored->expiry_notified_threshold);
        self::assertNull($stored->expiry_notified_at);
        self::assertNull($stored->expiry_claimed_until);

        $records = $this->capturedLogRecords();

        self::assertCount(1, $records);
        self::assertSame('sso.keys.expiry_dispatch_failed', $records[0]['message']);
        self::assertSame('warning', $records[0]['level']);
        self::assertSame(['key_id' => $key->id, 'exception' => \RuntimeException::class], $records[0]['context']);
        $this->assertNothingLoggedContains('a secret the listener held');

        self::assertSame(ExpiryNotice::NOTIFIED, $this->notifier()->notify($key, Clients::browser()));
        self::assertSame(2, $calls);
        self::assertSame(1, ConnectionKey::query()->whereKey($key->id)->sole()->expiry_notified_threshold);
    }

    /**
     * A dead reporter's claim blocks other runs until it runs out, then the
     * warning is sent.
     *
     * @return void
     */
    public function testADeadReportersClaimRunsOut(): void
    {
        $key = $this->key(self::DAY, ['expiry_claimed_until' => CarbonImmutable::parse(self::NOW)->addSeconds(10)]);

        self::assertSame(ExpiryNotice::CLAIMED, $this->notifier()->notify($key, Clients::browser()));
        $this->assertNoEvents();

        $this->clock->advance(9);

        self::assertSame(ExpiryNotice::CLAIMED, $this->notifier()->notify($key, Clients::browser()));
        $this->assertNoEvents();

        $this->clock->advance(1);

        self::assertSame(ExpiryNotice::NOTIFIED, $this->notifier()->notify($key, Clients::browser()));
        $this->assertEventSequence([KeyNearingExpiry::class]);
    }

    /**
     * A failure recording the marker after the dispatch propagates, and the
     * warning is sent again once the claim runs out.
     *
     * @return void
     */
    public function testACrashBetweenTheDispatchAndTheMarkerSendsAgain(): void
    {
        $key = $this->key(self::DAY);

        $this->failStatement('/^update .*expiry_notified_threshold/');

        try {
            $this->notifier()->notify($key, Clients::browser());
            self::fail('The failure did not propagate.');
        } catch (\Throwable $exception) {
            self::assertTrue(self::isInjectedFailure($exception));
        }

        $this->assertEventSequence([KeyNearingExpiry::class]);

        $stored = ConnectionKey::query()->whereKey($key->id)->sole();

        self::assertNull($stored->expiry_notified_threshold);
        self::assertNotNull($stored->expiry_claimed_until);

        self::assertSame(ExpiryNotice::CLAIMED, $this->notifier()->notify($key, Clients::browser()));

        $this->clock->advance(300);

        self::assertSame(ExpiryNotice::NOTIFIED, $this->notifier()->notify($key, Clients::browser()));
        $this->assertEventSequence([KeyNearingExpiry::class, KeyNearingExpiry::class]);
    }

    /**
     * A claim a deadlock rolled back is tried three times in all, and only then
     * propagates.
     *
     * @return void
     */
    public function testAClaimIsTriedThreeTimesInAll(): void
    {
        $key = $this->key(self::DAY);

        $this->deadlockStatement('/^update .*expiry_claimed_until/', 2);

        self::assertSame(ExpiryNotice::NOTIFIED, $this->notifier()->notify($key, Clients::browser()));
        self::assertSame(2, $this->databaseFailuresFired());

        $other = $this->key(self::DAY);

        $this->deadlockStatement('/^update .*expiry_claimed_until/', 3);

        try {
            $this->notifier()->notify($other, Clients::browser());
            self::fail('The third deadlock did not propagate.');
        } catch (\Throwable $exception) {
            self::assertTrue(self::isInjectedFailure($exception));
        }

        self::assertSame(5, $this->databaseFailuresFired());
    }

    /**
     * A failure taking the claim rolls back, propagates, and sends and records
     * nothing.
     *
     * @return void
     */
    public function testAFailureTakingTheClaimSendsNothing(): void
    {
        $key = $this->key(self::DAY);

        $this->failStatement('/^update .*expiry_claimed_until/');

        try {
            $this->notifier()->notify($key, Clients::browser());
            self::fail('The failure did not propagate.');
        } catch (\Throwable $exception) {
            self::assertTrue(self::isInjectedFailure($exception));
        }

        $this->assertNoEvents();
        self::assertNull(ConnectionKey::query()->whereKey($key->id)->sole()->expiry_claimed_until);
    }

    /**
     * A key removed, of a deleted connection, or retired past its overlap since
     * it was read is left alone.
     *
     * @return void
     */
    public function testAKeyNoLongerReportableIsLeftAlone(): void
    {
        $removed = $this->key(self::DAY);

        ConnectionKey::query()->whereKey($removed->id)->delete();

        self::assertNull($this->notifier()->notify($removed, Clients::browser()));

        $retired = $this->key(self::DAY);

        ConnectionKey::query()->whereKey($retired->id)->update(['state' => KeyState::RETIRING->value, 'retiring_until' => '2026-11-01 12:00:00']);

        self::assertNull($this->notifier()->notify($retired, Clients::browser()));
        self::assertNull(ConnectionKey::query()->whereKey($retired->id)->sole()->expiry_claimed_until);

        $orphan = $this->key(self::DAY);

        Connection::query()->whereKey($this->connection->id)->delete();

        self::assertNull($this->notifier()->notify($orphan, Clients::browser()));

        $this->assertNoEvents();
    }

    /**
     * A retiring key within its overlap, or with none set, and a key of another
     * state are reportable.
     *
     * @return void
     */
    public function testARetiringKeyInItsOverlapIsReportable(): void
    {
        $within = $this->key(self::DAY, ['state' => KeyState::RETIRING, 'retiring_until' => CarbonImmutable::parse(self::NOW)->addSecond()]);
        $open   = $this->key(self::DAY, ['state' => KeyState::RETIRING]);
        $next   = $this->key(self::DAY, ['state' => KeyState::NEXT]);

        self::assertSame(ExpiryNotice::NOTIFIED, $this->notifier()->notify($within, Clients::browser()));
        self::assertSame(ExpiryNotice::NOTIFIED, $this->notifier()->notify($open, Clients::browser()));
        self::assertSame(ExpiryNotice::NOTIFIED, $this->notifier()->notify($next, Clients::browser()));
    }

    /**
     * A key removed during the dispatch writes no row and raises nothing.
     *
     * @return void
     */
    public function testAKeyRemovedDuringTheDispatchIsNoFailure(): void
    {
        $key = $this->key(self::DAY);

        Event::listen(KeyNearingExpiry::class, static function () use ($key): void {
            ConnectionKey::query()->whereKey($key->id)->delete();
        });

        self::assertSame(ExpiryNotice::NOTIFIED, $this->notifier()->notify($key, Clients::browser()));
        self::assertFalse(ConnectionKey::query()->whereKey($key->id)->exists());
    }

    /**
     * What the locks find decides, so another reporter's warning or claim is
     * seen.
     *
     * @return void
     */
    public function testUnderTheLocksWhatIsStoredDecides(): void
    {
        $read = $this->key(self::DAY);

        ConnectionKey::query()->whereKey($read->id)->update(['expiry_notified_threshold' => 1]);

        self::assertSame(ExpiryNotice::ALREADY_NOTIFIED, $this->notifier()->notify($read, Clients::browser()));

        ConnectionKey::query()->whereKey($read->id)->update(['expiry_notified_threshold' => 0]);

        self::assertSame(ExpiryNotice::ALREADY_NOTIFIED, $this->notifier()->notify($read, Clients::browser()));

        ConnectionKey::query()->whereKey($read->id)->update(['expiry_notified_threshold' => 7]);

        self::assertSame(ExpiryNotice::NOTIFIED, $this->notifier()->notify($read, Clients::browser()));

        $this->assertEventSequence([KeyNearingExpiry::class]);
    }

    /**
     * Thresholds changing under the locks so none is reached is `not_due` and
     * sends nothing.
     *
     * @return void
     */
    public function testNoThresholdReachedUnderTheLocksIsNotDue(): void
    {
        $key = $this->key(10 * self::DAY);

        config()->set('sso.keys.expiry_thresholds', [5, 0]);

        self::assertSame(ExpiryNotice::NOT_DUE, $this->notifier()->notify($key, Clients::browser()));
        $this->assertNoEvents();
    }

    /**
     * An old reporter finishing late never makes the marker less urgent or
     * touches another's claim.
     *
     * @return void
     */
    public function testAnOldReporterNeverTakesTheMarkerBack(): void
    {
        $key = $this->key(self::DAY);

        Event::listen(KeyNearingExpiry::class, static function () use ($key): void {
            ConnectionKey::query()->whereKey($key->id)->update([
                'expiry_notified_threshold' => 0,
                'expiry_claimed_until'      => '2026-11-01 13:00:00',
            ]);
        });

        self::assertSame(ExpiryNotice::NOTIFIED, $this->notifier()->notify($key, Clients::browser()));

        $stored = ConnectionKey::query()->whereKey($key->id)->sole();

        self::assertSame(0, $stored->expiry_notified_threshold);
        self::assertSame('2026-11-01T13:00:00Z', $stored->expiry_claimed_until?->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * A dispatch failing with another reporter's claim in place leaves that
     * claim alone too.
     *
     * @return void
     */
    public function testAFailedDispatchLeavesAnotherReportersClaimAlone(): void
    {
        $key = $this->key(self::DAY);

        Event::listen(KeyNearingExpiry::class, static function () use ($key): never {

            ConnectionKey::query()->whereKey($key->id)->update(['expiry_claimed_until' => '2026-11-01 13:00:00']);

            throw new \RuntimeException('down');
        });

        self::assertSame(ExpiryNotice::FAILED, $this->notifier()->notify($key, Clients::browser()));
        self::assertSame('2026-11-01T13:00:00Z', ConnectionKey::query()->whereKey($key->id)->sole()->expiry_claimed_until?->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * A key of the connection whose validity ends the seconds given from now.
     *
     * @param  int  $endsIn
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function key(int $endsIn, array $attributes = []): ConnectionKey
    {
        $key = new ConnectionKey;

        $key->forceFill($attributes + [
            'connection_id' => $this->connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::EC,
            'key_bits'      => 256,
            'public_key'    => 'public',
            'fingerprint'   => hash('sha256', 'key-' . ++$this->keys),
            'not_after'     => CarbonImmutable::parse(self::NOW)->addSeconds($endsIn),
        ])->save();

        return $key;
    }

    /**
     * The notifier.
     *
     * @return \SineMacula\Laravel\Sso\Keys\ExpiryNotifier
     */
    private function notifier(): ExpiryNotifier
    {
        return app(ExpiryNotifier::class);
    }
}
