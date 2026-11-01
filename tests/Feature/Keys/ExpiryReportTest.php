<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\ExpiryReport;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for the nearing-expiry report (SSO-2.6, SSO-11.12, SSO-10.3):
 * the configured window and a given one, both edges of the window, expired rows
 * included, a retiring key past its overlap and a key with no end of validity
 * left out, the order, one `KeyNearingExpiry` per row with no acting identity,
 * a row whose connection is gone skipped, nothing written, every read on the
 * write connection, and a day count out of range refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExpiryReport::class)]
final class ExpiryReportTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The instant the clock holds. */
    private const string NOW = '2026-11-01T12:00:00Z';

    /** @var int The seconds in a day. */
    private const int DAY = 86400;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A SAML connection of the first tenant. */
    private Connection $saml;

    /** @var int The next certificate a key is made with, so each row has its own. */
    private int $certificate = 50;

    /**
     * Bind a fixed clock, create the tables and a SAML connection, and record
     * events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock(self::NOW));

        $this->createConnectionTables();

        $this->saml = $this->makeConnection(['protocol' => 'saml2']);

        $this->startRecordingEvents();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * With no window given, the report looks the default warning of 30 days
     * ahead: a key ending exactly then is reported, one ending a second later
     * is not.
     *
     * @return void
     */
    public function testTheDefaultWindowIsThirtyDays(): void
    {
        $soon  = $this->key(self::DAY);
        $edge  = $this->key(30 * self::DAY);
        $later = $this->key(30 * self::DAY + 1);

        self::assertSame([$soon->id, $edge->id], self::ids($this->report()->report()));
        self::assertNotContains($later->id, $this->reportedKeyIds());
    }

    /**
     * The configured warning, read on each call, sets the window.
     *
     * @return void
     */
    public function testTheConfiguredWarningSetsTheWindow(): void
    {
        $edge  = $this->key(10 * self::DAY);
        $later = $this->key(10 * self::DAY + 1);

        config()->set('sso.keys.expiry_warning_days', 10);

        self::assertSame([$edge->id], self::ids($this->report()->report()));

        config()->set('sso.keys.expiry_warning_days', 11);

        self::assertSame([$edge->id, $later->id], self::ids($this->report()->report()));
    }

    /**
     * A window given replaces the configured one, with both edges as before.
     *
     * @return void
     */
    public function testAGivenWindowReplacesTheConfiguredOne(): void
    {
        config()->set('sso.keys.expiry_warning_days', 30);

        $edge  = $this->key(3 * self::DAY);
        $later = $this->key(3 * self::DAY + 1);

        $this->key(10 * self::DAY);

        self::assertSame([$edge->id], self::ids($this->report()->report(3)));

        $this->assertEventSequence([KeyNearingExpiry::class]);

        self::assertSame([$edge->id, $later->id], self::ids($this->report()->report(4)));
    }

    /**
     * A key or certificate whose validity has already ended is reported, the
     * one ending at this very second included: its expiry is reported, never
     * enforced.
     *
     * @return void
     */
    public function testExpiredRowsAreIncluded(): void
    {
        $long   = $this->key(-400 * self::DAY);
        $just   = $this->key(-1);
        $now    = $this->key(0);
        $future = $this->key(self::DAY);

        self::assertSame([$long->id, $just->id, $now->id, $future->id], self::ids($this->report()->report(1)));
        self::assertSame(4, ConnectionKey::query()->count());
    }

    /**
     * A retiring key whose overlap has ended is left out; one still in its
     * overlap, and a current and a next key, are reported.
     *
     * @return void
     */
    public function testARetiringKeyPastItsOverlapIsExcluded(): void
    {
        $current = $this->key(self::DAY, KeyUse::SP_SIGNING, KeyState::CURRENT);
        $next    = $this->key(self::DAY, KeyUse::SP_SIGNING, KeyState::NEXT);
        $within  = $this->key(self::DAY, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, 1);

        $this->key(self::DAY, KeyUse::SP_SIGNING, KeyState::RETIRING, 0);
        $this->key(self::DAY, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, -self::DAY);

        $reported = self::ids($this->report()->report());

        self::assertCount(3, $reported);
        self::assertEqualsCanonicalizing([$current->id, $next->id, $within->id], $reported);
    }

    /**
     * A key with no end of validity is never reported, and with nothing to
     * report nothing is dispatched.
     *
     * @return void
     */
    public function testAKeyWithNoEndOfValidityIsNeverReported(): void
    {
        $this->key(null, KeyUse::SP_SIGNING, KeyState::CURRENT);

        self::assertSame([], $this->report()->report(ExpiryReport::MAX_DAYS));

        $this->assertNoEvents();
    }

    /**
     * The rows are ordered by the end of their validity, then by id, across
     * connections.
     *
     * @return void
     */
    public function testOrdersByEndOfValidityThenId(): void
    {
        $other = $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'saml2']);

        $later  = $this->key(5 * self::DAY, id: '01jbkeyc000000000000000000');
        $second = $this->key(2 * self::DAY, id: '01jbkeyb000000000000000000', connection: $other);
        $first  = $this->key(2 * self::DAY, id: '01jbkeya000000000000000000');
        $sooner = $this->key(self::DAY, id: '01jbkeyz000000000000000000', connection: $other);

        self::assertSame([$sooner->id, $first->id, $second->id, $later->id], self::ids($this->report()->report()));
        self::assertSame([$sooner->id, $first->id, $second->id, $later->id], $this->reportedKeyIds());
    }

    /**
     * Each row reported is dispatched once as `KeyNearingExpiry`, with its id,
     * use, fingerprint and end of validity, its connection, tenant and
     * protocol, and no acting identity; the summaries returned match.
     *
     * @return void
     */
    public function testReportsEachRowOnceWithNoActingIdentity(): void
    {
        $oidc = $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'oidc']);

        $certificate = $this->key(self::DAY);
        $assertion   = $this->key(2 * self::DAY, KeyUse::CLIENT_ASSERTION, KeyState::CURRENT, connection: $oidc);

        $summaries = $this->report()->report();

        $this->assertEventSequence([KeyNearingExpiry::class, KeyNearingExpiry::class]);

        $expected = [
            [$certificate, $this->saml, 'tenant-1', 'saml2'],
            [$assertion, $oidc, 'tenant-2', 'oidc'],
        ];

        foreach ($this->recordedEvents() as $index => $event) {

            [$key, $connection, $tenant, $protocol] = $expected[$index];

            self::assertInstanceOf(KeyNearingExpiry::class, $event);
            self::assertSame($key->id, $event->keyId);
            self::assertSame($key->use, $event->use);
            self::assertSame($key->fingerprint, $event->fingerprint);
            self::assertSame($key->not_after?->format('Y-m-d\TH:i:s\Z'), $event->notAfter->format('Y-m-d\TH:i:s\Z'));

            $context = $event->context();

            self::assertSame($connection->id, $context->connectionId);
            self::assertSame($tenant, $context->tenantId);
            self::assertSame($protocol, $context->protocol);
            self::assertNull($context->actingIdentityMorphClass);
            self::assertNull($context->actingIdentityId);
            self::assertNull($context->requestReference);
            self::assertNull($context->identityId);
            self::assertSame('2026-11-01T12:00:00.000000Z', $context->toArray()['occurred_at']);

            $summary = $summaries[$index];

            self::assertInstanceOf(KeySummary::class, $summary);
            self::assertSame($key->id, $summary->id);
            self::assertSame($connection->id, $summary->connectionId);
            self::assertSame($key->fingerprint, $summary->key->fingerprint);
        }
    }

    /**
     * A row whose connection is gone is skipped: neither returned nor reported.
     *
     * @return void
     */
    public function testSkipsARowWhoseConnectionIsGone(): void
    {
        $gone   = $this->makeConnection(['tenant_id' => 'tenant-2']);
        $orphan = $this->key(self::DAY, KeyUse::CLIENT_ASSERTION, KeyState::CURRENT, connection: $gone);
        $kept   = $this->key(2 * self::DAY);

        $gone->delete();

        self::assertSame([$kept->id], self::ids($this->report()->report()));
        self::assertSame([$kept->id], $this->reportedKeyIds());
        self::assertNotNull(ConnectionKey::query()->find($orphan->id));
    }

    /**
     * The report writes nothing: every row of both tables is as it was.
     *
     * @return void
     */
    public function testChangesNothing(): void
    {
        $this->key(-self::DAY);
        $this->key(self::DAY, KeyUse::SP_SIGNING, KeyState::CURRENT);
        $this->key(self::DAY, KeyUse::SP_SIGNING, KeyState::RETIRING, 0);

        $before = $this->rows();

        self::assertCount(2, $this->report()->report());
        self::assertSame($before, $this->rows());
    }

    /**
     * Every read is made on the write connection: with the read connection
     * unusable, the report still answers.
     *
     * @return void
     */
    public function testReadsTheWriteConnection(): void
    {
        $key = $this->key(self::DAY);

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('The read connection was used.');
        });

        try {
            $reported = $this->report()->report();
        } finally {
            DB::connection(StorageConnection::name())->setReadPdo(null);
        }

        self::assertSame([$key->id], self::ids($reported));
    }

    /**
     * The day counts a report may be given.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideDaysOutOfRange(): iterable
    {
        yield 'none' => [0];
        yield 'negative' => [-1];
        yield 'over a year' => [366];
        yield 'the largest integer' => [PHP_INT_MAX];
    }

    /**
     * A day count out of range is the application's mistake: refused with an
     * `InvalidArgumentException`, before anything is read or reported.
     *
     * @param  int  $days
     * @return void
     */
    #[DataProvider('provideDaysOutOfRange')]
    public function testRefusesADayCountOutOfRange(int $days): void
    {
        $this->key(-self::DAY);

        try {
            $this->report()->report($days);
            self::fail('A day count out of range was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('An expiry report looks 1 to 365 days ahead.', $exception->getMessage());
        }

        $this->assertNoEvents();
    }

    /**
     * The edges of the range are accepted.
     *
     * @return void
     */
    public function testAcceptsTheEdgesOfTheRange(): void
    {
        $key = $this->key(365 * self::DAY);

        self::assertSame([], $this->report()->report(1));
        self::assertSame([$key->id], self::ids($this->report()->report(365)));
        self::assertSame(1, ExpiryReport::MIN_DAYS);
        self::assertSame(365, ExpiryReport::MAX_DAYS);
    }

    /**
     * Make and save a key or certificate of the connection, the SAML one unless
     * another is given, whose validity ends the seconds given from now (never,
     * for `null`), with a certificate of its own.
     *
     * @param  ?int  $endsIn
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  ?int  $retiringFor
     * @param  ?string  $id
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function key(
        ?int $endsIn,
        KeyUse $use = KeyUse::IDP_SIGNING,
        ?KeyState $state = null,
        ?int $retiringFor = null,
        ?string $id = null,
        ?Connection $connection = null,
    ): ConnectionKey {
        $pem    = Certificates::distinct($this->certificate++);
        $masked = MaskedKey::fromCertificate($pem);
        $now    = CarbonImmutable::parse(self::NOW);
        $key    = new ConnectionKey;

        $attributes = [
            'connection_id'  => ($connection ?? $this->saml)->id,
            'use'            => $use,
            'state'          => $state,
            'key_type'       => KeyType::EC,
            'key_bits'       => 256,
            'certificate'    => $pem,
            'public_key'     => (string) $masked->publicKey,
            'private_key'    => $use->isOwnKey() ? 'encrypted-private-key' : null,
            'fingerprint'    => (string) $masked->fingerprint,
            'not_before'     => $now->subYear(),
            'not_after'      => $endsIn      === null ? null : $now->addSeconds($endsIn),
            'retiring_until' => $retiringFor === null ? null : $now->addSeconds($retiringFor),
        ];

        if ($id !== null) {
            $attributes['id'] = $id;
        }

        $key->forceFill($attributes)->save();

        return $key;
    }

    /**
     * The ids of the keys of the summaries, in order.
     *
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $summaries
     * @return list<string>
     */
    private static function ids(array $summaries): array
    {
        return array_map(static fn (KeySummary $summary): string => $summary->id, $summaries);
    }

    /**
     * The ids of the keys reported nearing expiry since recording last started,
     * in order.
     *
     * @return list<string>
     */
    private function reportedKeyIds(): array
    {
        $ids = [];

        foreach ($this->recordedEvents() as $event) {

            self::assertInstanceOf(KeyNearingExpiry::class, $event);

            $ids[] = $event->keyId;
        }

        return $ids;
    }

    /**
     * Every row of the connections table and the keys table, as stored, in
     * order of id.
     *
     * @return array{connections: list<array<array-key, mixed>>, keys: list<array<array-key, mixed>>}
     */
    private function rows(): array
    {
        $database = DB::connection(StorageConnection::name());
        $rows     = static fn (string $table): array => array_values(array_map(
            static fn (object $row): array => (array) $row,
            $database->table(StorageConnection::table($table))->orderBy('id')->get()->all(),
        ));

        return ['connections' => $rows('connections.table'), 'keys' => $rows('keys.table')];
    }

    /**
     * The report, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Keys\ExpiryReport
     */
    private function report(): ExpiryReport
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ExpiryReport::class);
    }
}
