<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\ExpiryNotifier;
use SineMacula\Laravel\Sso\Keys\ExpiryReport;
use SineMacula\Laravel\Sso\Keys\ExpiryRun;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Keys\Certificates;

/**
 * Query budgets for the expiry report (SSO-2.6, SSO-11.12):
 *
 * - a page is one select, and its connections one more when it holds a row, so
 *   an empty report is one select and a page already notified two, with no
 *   write and no lock; the next page's select follows a full page, and one that
 *   finds nothing reads no connections;
 * - a key warned of adds the claim's transaction, the connection's lock, the
 *   key's lock and the claim's update, and after the dispatch the marker's
 *   update and the release's: two reads and three writes;
 * - a key another reporter holds adds the two locks and no write; a dispatch
 *   that throws adds the claim and the release alone, recording nothing;
 * - a key whose connection is gone, and one in the window that has reached no
 *   threshold, read no lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExpiryReport::class)]
#[CoversClass(ExpiryNotifier::class)]
final class ExpiryReportQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections;

    /** @var int How many days are left of a key the report warns of, under the default thresholds of 30, 14, 7, 1 and 0. */
    private const int DAYS_LEFT = 5;

    /** @var int The most urgent of the default thresholds that a key with those days left has reached. */
    private const int THRESHOLD = 7;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the keys belong to. */
    private Connection $connection;

    /** @var \Carbon\CarbonImmutable When a key the report warns of ends. */
    private CarbonImmutable $ends;

    /**
     * Send the report's log lines nowhere, and make a connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.logging.channel', 'null');

        $this->connection = $this->makeConnection();
        $this->ends       = $this->clock->now()->addDays(self::DAYS_LEFT);
    }

    /**
     * An empty report is one select, and no read of any connection.
     *
     * @return void
     */
    public function testAnEmptyReportIsOneSelect(): void
    {
        $run = $this->assertQueryBudget(1, 0, fn (): ExpiryRun => $this->reportExpiries());

        self::assertSame(0, $run->listed);
    }

    /**
     * A page already notified is the page's select and its connections' select,
     * across any number of connections, with no lock and no write.
     *
     * @return void
     */
    public function testAPageAlreadyNotifiedIsTwoSelects(): void
    {
        $other = $this->makeConnection(['tenant_id' => 'tenant-2']);

        $this->storeKey($this->connection, ['expiry_notified_threshold' => self::THRESHOLD]);
        $this->storeKey($other, ['expiry_notified_threshold' => 0]);

        $run = $this->assertQueryBudget(2, 0, fn (): ExpiryRun => $this->reportExpiries());

        self::assertSame(2, $run->listed);
        self::assertSame(2, $run->count(ExpiryNotice::ALREADY_NOTIFIED));
    }

    /**
     * A key warned of is the page's two selects, then the claim's transaction,
     * then the marker's statement and the release's, in that order, with the
     * marker recorded and the claim released.
     *
     * @return void
     */
    public function testAKeyWarnedOfIsTheClaimAndTheMarker(): void
    {
        $key        = $this->storeKey($this->connection);
        $dispatched = 0;

        Event::listen(KeyNearingExpiry::class, static function () use (&$dispatched): void {
            $dispatched++;
        });

        $run = $this->assertQueryBudget(4, 3, fn (): ExpiryRun => $this->reportExpiries());

        $stored = ConnectionKey::query()->whereKey($key->id)->sole();

        self::assertSame(1, $run->count(ExpiryNotice::NOTIFIED));
        self::assertSame(['select', 'select', 'select', 'select', 'update', 'update', 'update'], self::verbs($this->statementsSent()));
        self::assertSame(self::THRESHOLD, $stored->expiry_notified_threshold);
        self::assertNull($stored->expiry_claimed_until);
        self::assertSame(1, $dispatched);
    }

    /**
     * A key warned of a less urgent threshold is warned of again, at the same
     * cost.
     *
     * @return void
     */
    public function testAKeyEscalatedCostsTheSame(): void
    {
        $this->storeKey($this->connection, ['expiry_notified_threshold' => 14]);

        $run = $this->assertQueryBudget(4, 3, fn (): ExpiryRun => $this->reportExpiries());

        self::assertSame(1, $run->count(ExpiryNotice::NOTIFIED));
    }

    /**
     * A key another reporter holds is the page's two selects and the two
     * locking reads, with no write.
     *
     * @return void
     */
    public function testAKeyClaimedElsewhereIsTwoLocksAndNoWrite(): void
    {
        $this->storeKey($this->connection, ['expiry_claimed_until' => $this->clock->now()->addMinute()]);

        $run = $this->assertQueryBudget(4, 0, fn (): ExpiryRun => $this->reportExpiries());

        self::assertSame(1, $run->count(ExpiryNotice::CLAIMED));
        self::assertSame(1, $run->listed);
    }

    /**
     * A dispatch that throws is the page's two selects, the claim's transaction
     * and the release, and records no marker.
     *
     * @return void
     */
    public function testADispatchThatThrowsReleasesTheClaimAlone(): void
    {
        $key = $this->storeKey($this->connection);

        Event::listen(KeyNearingExpiry::class, static function (): never {
            throw new \RuntimeException('A listener failed.');
        });

        $run = $this->assertQueryBudget(4, 2, fn (): ExpiryRun => $this->reportExpiries());

        $stored = ConnectionKey::query()->whereKey($key->id)->sole();

        self::assertSame(1, $run->count(ExpiryNotice::FAILED));
        self::assertNull($stored->expiry_notified_threshold);
        self::assertNull($stored->expiry_claimed_until);
    }

    /**
     * A key whose connection is gone is the page's two selects, and is neither
     * listed nor locked.
     *
     * @return void
     */
    public function testAKeyOfAConnectionGoneIsTwoSelects(): void
    {
        $key = $this->storeKey($this->connection);

        ConnectionKey::query()->whereKey($key->id)->update(['connection_id' => '01jbz0000000000000000000zz']);

        $run = $this->assertQueryBudget(2, 0, fn (): ExpiryRun => $this->reportExpiries());

        self::assertSame(0, $run->listed);
    }

    /**
     * A key in the window asked for that has reached no threshold is the page's
     * two selects, with no lock.
     *
     * @return void
     */
    public function testAKeyThatHasReachedNoThresholdTakesNoLock(): void
    {
        $this->storeKey($this->connection, ['not_after' => $this->clock->now()->addDays(60)]);

        $run = $this->assertQueryBudget(2, 0, fn (): ExpiryRun => $this->reportExpiries(90));

        self::assertSame(1, $run->count(ExpiryNotice::NOT_DUE));
        self::assertSame(1, $run->listed);
    }

    /**
     * Rows of `[keys, reads]`: a full page is followed by the next page's
     * select, and only a page that holds a row reads its connections.
     *
     * @return iterable<string, array{0: int, 1: int}>
     */
    public static function providePages(): iterable
    {
        yield 'a page but for one' => [ExpiryReport::PAGE_SIZE - 1, 2];
        yield 'a full page, and an empty one' => [ExpiryReport::PAGE_SIZE, 3];
        yield 'a full page, and one row more' => [ExpiryReport::PAGE_SIZE + 1, 4];
        yield 'two full pages, and an empty one' => [ExpiryReport::PAGE_SIZE * 2, 5];
    }

    /**
     * A report of many notified keys reads page after page.
     *
     * @param  int  $keys
     * @param  int  $reads
     * @return void
     */
    #[DataProvider('providePages')]
    public function testAReportReadsPageAfterPage(int $keys, int $reads): void
    {
        $this->storeNotifiedKeys($keys);

        $run = $this->assertQueryBudget($reads, 0, fn (): ExpiryRun => $this->reportExpiries());

        self::assertSame($keys, $run->listed);
        self::assertSame($keys, $run->count(ExpiryNotice::ALREADY_NOTIFIED));
    }

    /**
     * Run the report.
     *
     * @param  ?int  $withinDays
     * @return \SineMacula\Laravel\Sso\Keys\ExpiryRun
     */
    private function reportExpiries(?int $withinDays = null): ExpiryRun
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ExpiryReport::class)->report(Clients::browser(), $withinDays);
    }

    /**
     * Store a trusted certificate of the connection, ending within a threshold
     * and warned of nothing, unless the attributes given say otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function storeKey(Connection $connection, array $attributes = []): ConnectionKey
    {
        $key = new ConnectionKey;

        $key->forceFill($attributes + [
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'public_key'    => self::publicKey(),
            'fingerprint'   => hash('sha256', (string) Str::ulid()),
            'not_after'     => $this->ends,
        ])->save();

        return $key;
    }

    /**
     * Insert that many certificates of the connection in one statement per
     * hundred, each already warned of the threshold it has reached.
     *
     * @param  int  $keys
     * @return void
     */
    private function storeNotifiedKeys(int $keys): void
    {
        $model = new ConnectionKey;
        $table = DB::connection()->table($model->getTable());
        $now   = UtcDateTime::format($model, $this->clock->now());
        $ends  = UtcDateTime::format($model, $this->ends);
        $pem   = self::publicKey();

        foreach (array_chunk(range(1, $keys), 100) as $chunk) {
            $table->insert(array_map(fn (int $number): array => [
                'id'                        => strtolower((string) Str::ulid()),
                'connection_id'             => $this->connection->id,
                'use'                       => KeyUse::IDP_SIGNING->value,
                'key_type'                  => KeyType::RSA->value,
                'key_bits'                  => 2048,
                'public_key'                => $pem,
                'fingerprint'               => hash('sha256', "key-{$number}"),
                'not_after'                 => $ends,
                'expiry_notified_threshold' => self::THRESHOLD,
                'created_at'                => $now,
                'updated_at'                => $now,
            ], $chunk));
        }
    }

    /**
     * A real public key, since the report reads the summary of each key it
     * lists.
     *
     * @return string
     */
    private static function publicKey(): string
    {
        return (string) MaskedKey::fromCertificate(Certificates::rsa2048())->publicKey;
    }

    /**
     * The first word of each statement, in lower case.
     *
     * @param  list<string>  $sent
     * @return list<string>
     */
    private static function verbs(array $sent): array
    {
        return array_map(static fn (string $sql): string => strtolower(strtok(ltrim($sql), ' ') ?: ''), $sent);
    }
}
