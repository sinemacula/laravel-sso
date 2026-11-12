<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Console\ExpiringKeysCommand;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for `sso:keys:expiring`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExpiringKeysCommand::class)]
final class ExpiringKeysCommandTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The instant the clock holds. */
    private const string NOW = '2026-11-01T12:00:00Z';

    /** @var int The seconds in a day. */
    private const int DAY = 86400;

    /** @var string The summary of a run that listed nothing. */
    private const string NOTHING = 'Keys listed: 0, expired 0; warnings: notified 0, already_notified 0, not_due 0, claimed 0, failed 0';

    /** @var \SineMacula\Laravel\Sso\Models\Connection A connection. */
    private Connection $connection;

    /**
     * Bind a fixed clock, create the tables and a connection, and record
     * events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock(self::NOW));

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2']);

        $this->startRecordingEvents();
    }

    /**
     * With nothing nearing expiry, the summary alone, and it passes.
     *
     * @return void
     */
    public function testWithNothingPrintsTheSummaryAlone(): void
    {
        [$code, $output] = $this->expiring();

        self::assertSame(0, $code);
        self::assertSame([self::NOTHING], $output);
    }

    /**
     * A line per key, expired first, then the counts, with no key material and
     * exit 0.
     *
     * @return void
     */
    public function testPrintsEachKeyAndTheCounts(): void
    {
        $expired = $this->key(-self::DAY, 50);
        $soon    = $this->key(self::DAY, 51);

        [$code, $output] = $this->expiring();

        self::assertSame(0, $code);
        self::assertSame([
            sprintf('[expired] key %s (connection %s, idp_signing) ends 2026-10-31T12:00:00Z, threshold 0: notified', $expired->id, $this->connection->id),
            sprintf('[expiring] key %s (connection %s, idp_signing) ends 2026-11-02T12:00:00Z, threshold 1: notified', $soon->id, $this->connection->id),
            'Keys listed: 2, expired 1; warnings: notified 2, already_notified 0, not_due 0, claimed 0, failed 0',
        ], $output);
        self::assertStringNotContainsString('BEGIN', implode("\n", $output));
        self::assertStringNotContainsString((string) $expired->certificate, implode("\n", $output));
    }

    /**
     * A second run lists the same keys and sends nothing.
     *
     * @return void
     */
    public function testASecondRunStillListsWhatWasNotified(): void
    {
        $expired = $this->key(-self::DAY, 50);

        $this->expiring();

        [$code, $output] = $this->expiring();

        self::assertSame(0, $code);
        self::assertSame([
            sprintf('[expired] key %s (connection %s, idp_signing) ends 2026-10-31T12:00:00Z, threshold 0: already_notified', $expired->id, $this->connection->id),
            'Keys listed: 1, expired 1; warnings: notified 0, already_notified 1, not_due 0, claimed 0, failed 0',
        ], $output);
        $this->assertEventSequence([KeyNearingExpiry::class]);
    }

    /**
     * `--days` lists further ahead.
     *
     * @return void
     */
    public function testDaysListsFurtherAhead(): void
    {
        $far = $this->key(40 * self::DAY, 50);

        self::assertSame([self::NOTHING], $this->expiring()[1]);

        [$code, $output] = $this->expiring(['--days' => '60']);

        self::assertSame(0, $code);
        self::assertSame([
            sprintf('[expiring] key %s (connection %s, idp_signing) ends 2026-12-11T12:00:00Z, threshold none: not_due', $far->id, $this->connection->id),
            'Keys listed: 1, expired 0; warnings: notified 0, already_notified 0, not_due 1, claimed 0, failed 0',
        ], $output);
    }

    /**
     * A malformed `--days` stops the run by class alone.
     *
     * @return void
     */
    public function testAMalformedDaysStopsTheRun(): void
    {
        foreach (['0', '366', 'soon', '1.5'] as $days) {

            [$code, $output] = $this->expiring(['--days' => $days]);

            self::assertSame(1, $code);
            self::assertSame(['The expiry report stopped on InvalidArgumentException.'], $output);
        }
    }

    /**
     * A dispatch that threw exits non-zero and is sent again next run.
     *
     * @return void
     */
    public function testADispatchThatThrewExitsNonZeroAndIsSentAgain(): void
    {
        $failing = $this->key(self::DAY, 50);
        $next    = $this->key(2 * self::DAY, 51);
        $failed  = false;

        Event::listen(KeyNearingExpiry::class, static function () use (&$failed): void {
            if (!$failed) {
                $failed = true;

                throw new \RuntimeException('a secret the listener held');
            }
        });

        [$code, $output] = $this->expiring();

        self::assertSame(1, $code);
        self::assertSame([
            sprintf('[expiring] key %s (connection %s, idp_signing) ends 2026-11-02T12:00:00Z, threshold 1: failed', $failing->id, $this->connection->id),
            sprintf('[expiring] key %s (connection %s, idp_signing) ends 2026-11-03T12:00:00Z, threshold 7: notified', $next->id, $this->connection->id),
            'Keys listed: 2, expired 0; warnings: notified 1, already_notified 0, not_due 0, claimed 0, failed 1',
        ], $output);
        self::assertStringNotContainsString('a secret the listener held', implode("\n", $output));

        [$code, $output] = $this->expiring();

        self::assertSame(0, $code);
        self::assertSame('Keys listed: 2, expired 0; warnings: notified 1, already_notified 1, not_due 0, claimed 0, failed 0', $output[2]);
    }

    /**
     * Inside a transaction the run stops by class alone.
     *
     * @return void
     */
    public function testAnExceptionStopsTheRunByClassAlone(): void
    {
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        try {
            [$code, $output] = $this->expiring();
        } finally {
            $database->rollBack();
        }

        self::assertSame(1, $code);
        self::assertSame(['The expiry report stopped on LogicException.'], $output);
    }

    /**
     * A key of the connection whose validity ends the seconds given from now.
     *
     * @param  int  $endsIn
     * @param  int  $certificate
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function key(int $endsIn, int $certificate): ConnectionKey
    {
        $pem    = Certificates::distinct($certificate);
        $masked = MaskedKey::fromCertificate($pem);
        $key    = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $this->connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::EC,
            'key_bits'      => 256,
            'certificate'   => $pem,
            'public_key'    => (string) $masked->publicKey,
            'fingerprint'   => (string) $masked->fingerprint,
            'not_after'     => CarbonImmutable::parse(self::NOW)->addSeconds($endsIn),
        ])->save();

        return $key;
    }

    /**
     * Run the command and answer its exit code and output lines.
     *
     * @param  array<string, mixed>  $options
     * @return array{0: int, 1: list<string>}
     */
    private function expiring(array $options = []): array
    {
        $code   = Artisan::call('sso:keys:expiring', $options);
        $output = array_values(array_filter(explode("\n", trim(Artisan::output())), static fn (string $line): bool => $line !== ''));

        return [$code, $output];
    }
}
