<?php

declare(strict_types = 1);

namespace Tests\Integration\Keys;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\ExpiryNotifier;
use SineMacula\Laravel\Sso\Keys\ExpiryReport;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Tests\Concerns\RacesProcesses;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Races runs of the expiry report across processes, each with its own database
 * connection, on PostgreSQL and MySQL (SSO-2.6, SSO-11.12): with nothing
 * failing the claim lets one reporter send each warning, each key's marker is
 * written and no claim is left; and a second reporter that finds a key claimed
 * while the holder dispatches, on a signal from the holder and not by timing,
 * is `claimed` and sends nothing, and every key is still listed by both.
 *
 * A report refuses a caller's transaction, so each racer runs plainly; the
 * refusal has its test in `ExpiryReportTest`. Skipped on SQLite, whose
 * in-memory database each process would have to itself, and where `pcntl` is
 * not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExpiryReport::class)]
#[CoversClass(ExpiryNotifier::class)]
final class ConcurrentExpiryReportersTest extends TestCase
{
    use RacesProcesses, UsesConnections;

    /** @var int Processes racing. */
    private const int PROCESSES = 6;

    /** @var int Keys due a warning. */
    private const int KEYS = 10;

    /** @var string The instant the clock holds. */
    private const string NOW = '2026-11-01T12:00:00Z';

    /** @var int How many keys have been made, so each has its own fingerprint. */
    private int $keys = 0;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the keys belong to. */
    private Connection $connection;

    /**
     * Skip where processes cannot share the database; bind a fixed clock, make
     * the certificate before any process forks, and create the tables and the
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

        $this->app?->instance(Clock::class, new FixedClock(self::NOW));

        Certificates::distinct(50);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2']);
    }

    /**
     * Remove what the race used.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->tearDownRace();

        parent::tearDown();
    }

    /**
     * Reporters racing over the same keys send each warning once between them,
     * and leave every marker written and no claim behind.
     *
     * @return void
     */
    public function testRacingReportersSendEachWarningOnce(): void
    {
        for ($key = 0; $key < self::KEYS; $key++) {
            $this->key(86400);
        }

        $racers = array_fill(0, self::PROCESSES, static function (): array {

            $sent = [];

            Event::listen(KeyNearingExpiry::class, static function (KeyNearingExpiry $event) use (&$sent): void {
                $sent[] = $event->keyId;
            });

            $run = app(ExpiryReport::class)->report();

            return ['sent' => $sent, 'listed' => $run->listed];
        });

        $results = $this->assertRacersSucceeded($this->race($racers));

        $sent = array_merge(...array_column($results, 'sent'));

        sort($sent);

        $ids = ConnectionKey::query()->pluck('id')->all();

        sort($ids);

        self::assertSame($ids, $sent);
        self::assertSame(array_fill(0, self::PROCESSES, self::KEYS), array_column($results, 'listed'));
        self::assertSame(self::KEYS, ConnectionKey::query()->where('expiry_notified_threshold', 1)->whereNull('expiry_claimed_until')->count());
    }

    /**
     * A reporter that finds a key claimed while its holder is dispatching sends
     * nothing and says so, listing the key all the same; the holder records it.
     *
     * @return void
     */
    public function testAReporterFindingAKeyClaimedSendsNothing(): void
    {
        $this->key(86400);

        $reports = $this->race([
            function (): array {

                $sent = 0;

                Event::listen(KeyNearingExpiry::class, function () use (&$sent): void {

                    $sent++;

                    $this->signal('dispatching');
                    $this->awaitSignal('looked');
                });

                return ['run' => app(ExpiryReport::class)->report()->jsonSerialize(), 'count' => $sent];
            },
            function (): array {

                $this->awaitSignal('dispatching');

                $sent = 0;

                Event::listen(KeyNearingExpiry::class, static function () use (&$sent): void {
                    $sent++;
                });

                try {
                    $run = app(ExpiryReport::class)->report();
                } finally {
                    $this->signal('looked');
                }

                return ['count' => $sent, 'run' => $run->jsonSerialize()];
            },
        ]);

        [$holder, $other] = $this->assertRacersSucceeded($reports);

        self::assertSame(1, $holder['run']['notices'][ExpiryNotice::NOTIFIED->value]);
        self::assertSame(1, $holder['run']['listed']);
        self::assertSame(1, $holder['count']);
        self::assertSame(0, $other['count']);
        self::assertSame(1, $other['run']['notices'][ExpiryNotice::CLAIMED->value]);
        self::assertSame(1, $other['run']['listed']);

        $stored = ConnectionKey::query()->sole();

        self::assertSame(1, $stored->expiry_notified_threshold);
        self::assertNull($stored->expiry_claimed_until);
    }

    /**
     * A key of the connection whose validity ends the seconds given from now.
     *
     * @param  int  $endsIn
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function key(int $endsIn): ConnectionKey
    {
        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $this->connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::EC,
            'key_bits'      => 256,
            'public_key'    => (string) MaskedKey::fromCertificate(Certificates::distinct(50))->publicKey,
            'fingerprint'   => hash('sha256', 'key-' . ++$this->keys),
            'not_after'     => CarbonImmutable::parse(self::NOW)->addSeconds($endsIn),
        ])->save();

        return $key;
    }
}
