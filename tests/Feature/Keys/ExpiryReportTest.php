<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\ExpiringKey;
use SineMacula\Laravel\Sso\Keys\ExpiryNotifier;
use SineMacula\Laravel\Sso\Keys\ExpiryReport;
use SineMacula\Laravel\Sso\Keys\ExpiryRun;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\Fixtures\Pruning\TickingClock;
use Tests\TestCase;

/**
 * Feature tests for the nearing-expiry report (SSO-2.6, SSO-11.12, SSO-10.3):
 * the window from the largest threshold and a given one, both edges, expired
 * rows included, a retiring key past its overlap and a key with no end of
 * validity left out, the order across pages, one `KeyNearingExpiry` for the
 * most urgent threshold reached with no acting identity, monotonic escalation,
 * what a change of the thresholds does, what is listed whatever was notified, a
 * row whose connection is gone skipped, an open transaction refused, every read
 * on the write connection, a connection of the storage's own, renamed and
 * schema-qualified tables, and a day count out of range refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExpiryReport::class)]
#[CoversClass(ExpiryRun::class)]
#[CoversClass(ExpiringKey::class)]
#[CoversClass(ExpiryNotifier::class)]
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

        $this->usePackageTables();

        $this->saml = $this->makeConnection(['protocol' => 'saml2']);

        $this->startRecordingEvents();
    }

    /**
     * With no window given, the report lists up to the largest threshold, 30
     * days by default: a key ending exactly then is listed, one ending a second
     * later is not.
     *
     * @return void
     */
    public function testTheDefaultWindowIsTheLargestThreshold(): void
    {
        $soon  = $this->key(self::DAY);
        $edge  = $this->key(30 * self::DAY);
        $later = $this->key(30 * self::DAY + 1);

        self::assertSame([$soon->id, $edge->id], $this->listed());
        self::assertNotContains($later->id, $this->reportedKeyIds());
    }

    /**
     * The configured thresholds, read on each call, set the window.
     *
     * @return void
     */
    public function testTheConfiguredThresholdsSetTheWindow(): void
    {
        $edge  = $this->key(10 * self::DAY);
        $later = $this->key(10 * self::DAY + 1);

        config()->set('sso.keys.expiry_thresholds', [10, 0]);

        self::assertSame([$edge->id], $this->listed());

        config()->set('sso.keys.expiry_thresholds', [11, 0]);

        self::assertSame([$edge->id, $later->id], $this->listed());
    }

    /**
     * Thresholds of 0 alone list what has ended, and warn of nothing else.
     *
     * @return void
     */
    public function testAThresholdOfNothingListsWhatHasEnded(): void
    {
        config()->set('sso.keys.expiry_thresholds', [0]);

        $ended = $this->key(0);

        $this->key(1);

        self::assertSame([$ended->id], $this->listed());
        self::assertSame([$ended->id], $this->reportedKeyIds());
    }

    /**
     * A window given replaces the default for what is listed, with both edges
     * as before.
     *
     * @return void
     */
    public function testAGivenWindowReplacesTheDefault(): void
    {
        $edge  = $this->key(3 * self::DAY);
        $later = $this->key(3 * self::DAY + 1);

        $this->key(10 * self::DAY);

        self::assertSame([$edge->id], $this->listed(3));
        self::assertSame([$edge->id, $later->id], $this->listed(4));
    }

    /**
     * A narrower window lists less but warns of the same keys: a threshold a
     * key has reached is not missed because an operator looked at the next
     * three days. Those it does not list are still counted among the notices.
     *
     * @return void
     */
    public function testANarrowerWindowStillWarnsOfEveryKeyDue(): void
    {
        $near = $this->key(self::DAY);
        $far  = $this->key(10 * self::DAY);

        $entries = [];
        $run     = $this->report()->report(Clients::browser(), 3, static function (ExpiringKey $entry) use (&$entries): void {
            $entries[] = $entry->key->id;
        });

        self::assertSame([$near->id], $entries);
        self::assertSame(1, $run->listed);
        self::assertSame(2, $run->count(ExpiryNotice::NOTIFIED));
        self::assertSame([$near->id, $far->id], $this->reportedKeyIds());
    }

    /**
     * A wider window lists more, a key that has reached no threshold marked as
     * not due, and warns of nothing beyond the largest threshold.
     *
     * @return void
     */
    public function testAWiderWindowListsWhatHasReachedNoThreshold(): void
    {
        $far = $this->key(40 * self::DAY);

        $entries = $this->entries(60);

        self::assertCount(1, $entries);
        self::assertSame($far->id, $entries[0]->key->id);
        self::assertNull($entries[0]->thresholdDays);
        self::assertSame(ExpiryNotice::NOT_DUE, $entries[0]->notice);
        self::assertFalse($entries[0]->expired);
        $this->assertNoEvents();
    }

    /**
     * A key or certificate whose validity has already ended is listed, the one
     * ending at this very second included, as expired: its expiry is reported,
     * never enforced.
     *
     * @return void
     */
    public function testExpiredRowsAreIncluded(): void
    {
        $long   = $this->key(-400 * self::DAY);
        $just   = $this->key(-1);
        $now    = $this->key(0);
        $future = $this->key(self::DAY);

        $entries = $this->entries(1);

        self::assertSame([$long->id, $just->id, $now->id, $future->id], array_map(static fn (ExpiringKey $entry): string => $entry->key->id, $entries));
        self::assertSame([true, true, true, false], array_map(static fn (ExpiringKey $entry): bool => $entry->expired, $entries));
        self::assertSame(4, ConnectionKey::query()->count());
    }

    /**
     * A retiring key whose overlap has ended is left out; one still in its
     * overlap, and a current and a next key, are listed.
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

        $listed = $this->listed();

        self::assertCount(3, $listed);
        self::assertEqualsCanonicalizing([$current->id, $next->id, $within->id], $listed);
    }

    /**
     * A key with no end of validity is never listed, and with nothing to list
     * nothing is dispatched.
     *
     * @return void
     */
    public function testAKeyWithNoEndOfValidityIsNeverReported(): void
    {
        $this->key(null, KeyUse::SP_SIGNING, KeyState::CURRENT);

        self::assertSame([], $this->listed(ExpiryReport::MAX_DAYS));

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

        self::assertSame([$sooner->id, $first->id, $second->id, $later->id], $this->listed());
        self::assertSame([$sooner->id, $first->id, $second->id, $later->id], $this->reportedKeyIds());
    }

    /**
     * More keys than a page are all listed, once each and in order, those
     * sharing a second by their id, in one query per page and connection list.
     *
     * @return void
     */
    public function testPagesCoverEveryKeyAcrossTies(): void
    {
        $now    = CarbonImmutable::parse(self::NOW)->addDay();
        $public = (string) MaskedKey::fromCertificate(Certificates::distinct(40))->publicKey;
        $ids    = [];

        for ($row = 0; $row < ExpiryReport::PAGE_SIZE + 3; $row++) {

            $id    = sprintf('01jbkey%019d', $row);
            $ids[] = $id;

            DB::connection(StorageConnection::name())->table('sso_keys')->insert([
                'id'                        => $id,
                'connection_id'             => $this->saml->id,
                'use'                       => KeyUse::IDP_SIGNING->value,
                'key_type'                  => KeyType::EC->value,
                'key_bits'                  => 256,
                'public_key'                => $public,
                'fingerprint'               => hash('sha256', $id),
                'not_after'                 => $now->format('Y-m-d H:i:s'),
                'expiry_notified_threshold' => 1,
                'created_at'                => $now->format('Y-m-d H:i:s'),
                'updated_at'                => $now->format('Y-m-d H:i:s'),
            ]);
        }

        self::assertSame($ids, $this->listed());
        $this->assertNoEvents();
    }

    /**
     * Each row due is dispatched once as `KeyNearingExpiry`, with its id, use,
     * fingerprint, end of validity and the threshold reached, its connection,
     * tenant and protocol, and no acting identity; the entries match.
     *
     * @return void
     */
    public function testReportsEachRowOnceWithNoActingIdentity(): void
    {
        $oidc = $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'oidc']);

        $certificate = $this->key(self::DAY);
        $assertion   = $this->key(2 * self::DAY, KeyUse::CLIENT_ASSERTION, KeyState::CURRENT, connection: $oidc);

        $entries = $this->entries();

        $this->assertEventSequence([KeyNearingExpiry::class, KeyNearingExpiry::class]);

        $expected = [
            [$certificate, $this->saml, 'tenant-1', 'saml2', 1],
            [$assertion, $oidc, 'tenant-2', 'oidc', 7],
        ];

        foreach ($this->recordedEvents() as $index => $event) {

            [$key, $connection, $tenant, $protocol, $threshold] = $expected[$index];

            self::assertInstanceOf(KeyNearingExpiry::class, $event);
            self::assertSame($key->id, $event->keyId);
            self::assertSame($key->use, $event->use);
            self::assertSame($key->fingerprint, $event->fingerprint);
            self::assertSame($key->not_after?->format('Y-m-d\TH:i:s\Z'), $event->notAfter->format('Y-m-d\TH:i:s\Z'));
            self::assertSame($threshold, $event->thresholdDays);

            $context = $event->context();

            self::assertSame($connection->id, $context->connectionId);
            self::assertSame($tenant, $context->connectionTenantId);
            self::assertSame($protocol, $context->protocol);
            self::assertNull($context->actingIdentityMorphClass);
            self::assertNull($context->actingIdentityId);
            self::assertNull($context->requestReference);
            self::assertNull($context->identityId);
            self::assertSame('2026-11-01T12:00:00.000000Z', $context->toArray()['occurred_at']);

            $entry = $entries[$index];

            self::assertSame($key->id, $entry->key->id);
            self::assertSame($connection->id, $entry->key->connectionId);
            self::assertSame($key->fingerprint, $entry->key->key->fingerprint);
            self::assertSame($threshold, $entry->thresholdDays);
            self::assertSame(ExpiryNotice::NOTIFIED, $entry->notice);
        }
    }

    /**
     * Rows of `[seconds left, the threshold reached]`: the most urgent
     * threshold reached, at each side of every default threshold.
     *
     * @return iterable<string, array{0: int, 1: ?int}>
     */
    public static function provideThresholds(): iterable
    {
        yield 'just past 30 days' => [30 * self::DAY + 1, null];
        yield 'at 30 days' => [30 * self::DAY, 30];
        yield 'just past 14 days' => [14 * self::DAY + 1, 30];
        yield 'at 14 days' => [14 * self::DAY, 14];
        yield 'just past 7 days' => [7 * self::DAY + 1, 14];
        yield 'at 7 days' => [7 * self::DAY, 7];
        yield 'just past a day' => [self::DAY + 1, 7];
        yield 'at a day' => [self::DAY, 1];
        yield 'a second left' => [1, 1];
        yield 'at the end' => [0, 0];
        yield 'a second past the end' => [-1, 0];
        yield 'long past the end' => [-400 * self::DAY, 0];
    }

    /**
     * The event names the most urgent threshold reached, and only one is sent,
     * whatever was passed since the last run.
     *
     * @param  int  $left
     * @param  ?int  $threshold
     * @return void
     */
    #[DataProvider('provideThresholds')]
    public function testWarnsOfTheMostUrgentThresholdReached(int $left, ?int $threshold): void
    {
        $this->key($left);

        $this->report()->report(Clients::browser(), 60);

        if ($threshold === null) {
            $this->assertNoEvents();

            return;
        }

        $this->assertEventSequence([KeyNearingExpiry::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(KeyNearingExpiry::class, $event);
        self::assertSame($threshold, $event->thresholdDays);
    }

    /**
     * A warning is sent once per threshold, however often the report runs, and
     * the marker is written: the threshold, when, and no claim left behind.
     *
     * @return void
     */
    public function testAWarningIsSentOnceAndRecorded(): void
    {
        $key = $this->key(self::DAY);

        self::assertSame([ExpiryNotice::NOTIFIED], $this->notices());
        self::assertSame([ExpiryNotice::ALREADY_NOTIFIED], $this->notices());
        self::assertSame([ExpiryNotice::ALREADY_NOTIFIED], $this->notices());

        $this->assertEventSequence([KeyNearingExpiry::class]);

        $stored = ConnectionKey::query()->whereKey($key->id)->sole();

        self::assertSame(1, $stored->expiry_notified_threshold);
        self::assertSame(self::NOW, $stored->expiry_notified_at?->format('Y-m-d\TH:i:s\Z'));
        self::assertNull($stored->expiry_claimed_until);
    }

    /**
     * A key escalates as time passes: each more urgent threshold is warned of
     * once, the expired one last, and those passed while nothing ran are
     * skipped.
     *
     * @return void
     */
    public function testEscalatesAndSkipsWhatItPassed(): void
    {
        $clock = new FixedClock(self::NOW);

        $this->app?->instance(Clock::class, $clock);

        $this->key(20 * self::DAY);

        $thresholds = [];

        foreach ([0, 5, 1, 5, 9, 1] as $days) {

            $clock->advance($days * self::DAY);

            $this->report()->report(Clients::browser());

            $last = $this->recordedEvents()[count($this->recordedEvents()) - 1] ?? null;

            self::assertInstanceOf(KeyNearingExpiry::class, $last);

            $thresholds[] = $last->thresholdDays;
        }

        // 20 days left: 30; 15: 30 again, nothing new; 14: 14; 9: 14 again; at
        // the end: 0, skipping 7 and 1; a day past: 0 again.
        self::assertSame([30, 30, 14, 14, 0, 0], $thresholds);
        self::assertCount(3, $this->recordedEvents());
    }

    /**
     * After a change of the thresholds the report only ever escalates: a less
     * urgent threshold than the last warned of stays quiet, and the next more
     * urgent one is warned of.
     *
     * @return void
     */
    public function testAChangeOfTheThresholdsNeverGoesBackToALessUrgentWarning(): void
    {
        $clock = new FixedClock(self::NOW);

        $this->app?->instance(Clock::class, $clock);

        $key = $this->key(10 * self::DAY);

        $this->report()->report(Clients::browser());

        self::assertSame(14, ConnectionKey::query()->whereKey($key->id)->sole()->expiry_notified_threshold);

        config()->set('sso.keys.expiry_thresholds', [60, 30, 5, 0]);

        self::assertSame([ExpiryNotice::ALREADY_NOTIFIED], $this->notices());
        self::assertCount(1, $this->recordedEvents());

        $clock->advance(5 * self::DAY);

        self::assertSame([ExpiryNotice::NOTIFIED], $this->notices());

        $event = $this->recordedEvents()[1];

        self::assertInstanceOf(KeyNearingExpiry::class, $event);
        self::assertSame(5, $event->thresholdDays);
    }

    /**
     * What is listed does not depend on what was notified: an expired key
     * already warned of is still listed on every run, as expired.
     *
     * @return void
     */
    public function testAKeyAlreadyNotifiedIsStillListed(): void
    {
        $key = $this->key(-self::DAY);

        $this->report()->report(Clients::browser());

        $entries = $this->entries();

        self::assertCount(1, $entries);
        self::assertSame($key->id, $entries[0]->key->id);
        self::assertTrue($entries[0]->expired);
        self::assertSame(0, $entries[0]->thresholdDays);
        self::assertSame(ExpiryNotice::ALREADY_NOTIFIED, $entries[0]->notice);
    }

    /**
     * A key already warned of takes no lock and writes nothing.
     *
     * @return void
     */
    public function testAKeyAlreadyNotifiedTakesNoLock(): void
    {
        $this->key(self::DAY);

        $this->report()->report(Clients::browser());

        $statements = [];

        DB::connection(StorageConnection::name())->listen(static function ($query) use (&$statements): void {
            $statements[] = strtolower($query->sql);
        });

        $this->report()->report(Clients::browser());

        self::assertSame(['select', 'select'], array_map(static fn (string $sql): string => substr($sql, 0, 6), $statements));
    }

    /**
     * An entry encodes in snake_case with its time in UTC, and holds no key.
     *
     * @return void
     */
    public function testAnEntryEncodesItsPublicFacts(): void
    {
        $key = $this->key(-self::DAY);

        self::assertSame([
            'key_id'         => $key->id,
            'connection_id'  => $this->saml->id,
            'use'            => 'idp_signing',
            'not_after'      => '2026-10-31T12:00:00Z',
            'expired'        => true,
            'threshold_days' => 0,
            'notice'         => 'notified',
        ], $this->entries()[0]->jsonSerialize());
    }

    /**
     * The run counts what it listed and how each key ended.
     *
     * @return void
     */
    public function testTheRunCountsWhatItDid(): void
    {
        $this->key(-self::DAY);
        $this->key(self::DAY);
        $this->key(40 * self::DAY);

        $run = $this->report()->report(Clients::browser(), 60);

        self::assertSame(3, $run->listed);
        self::assertSame(1, $run->expired);
        self::assertSame(2, $run->count(ExpiryNotice::NOTIFIED));
        self::assertSame(1, $run->count(ExpiryNotice::NOT_DUE));
        self::assertSame(0, $run->count(ExpiryNotice::FAILED));
        self::assertFalse($run->hasFailures());
        self::assertSame(
            ['listed' => 3, 'expired' => 1, 'notices' => ['notified' => 2, 'already_notified' => 0, 'not_due' => 1, 'claimed' => 0, 'failed' => 0]],
            $run->jsonSerialize(),
        );
    }

    /**
     * The window is counted from the one instant the run read, however the
     * clock moves as it goes: a key's threshold and listing do not drift.
     *
     * @return void
     */
    public function testTheWindowIsCountedFromOneInstant(): void
    {
        $key   = $this->key(30 * self::DAY + 1);
        $clock = new TickingClock(self::NOW, 60);

        $this->app?->instance(Clock::class, $clock);

        self::assertSame([], $this->listed());
        self::assertSame(1, $clock->reads);
        self::assertTrue(ConnectionKey::query()->whereKey($key->id)->exists());
    }

    /**
     * A row whose connection is gone is skipped: neither listed nor reported.
     *
     * @return void
     */
    public function testSkipsARowWhoseConnectionIsGone(): void
    {
        $gone   = $this->makeConnection(['tenant_id' => 'tenant-2']);
        $orphan = $this->key(self::DAY, KeyUse::CLIENT_ASSERTION, KeyState::CURRENT, connection: $gone);
        $kept   = $this->key(2 * self::DAY);

        $gone->delete();

        self::assertSame([$kept->id], $this->listed());
        self::assertSame([$kept->id], $this->reportedKeyIds());
        self::assertNotNull(ConnectionKey::query()->find($orphan->id));
    }

    /**
     * A row whose connection is gone is skipped before anything is judged of
     * it: one that has reached no threshold is neither listed nor counted.
     *
     * @return void
     */
    public function testSkipsARowWhoseConnectionIsGoneBeforeJudgingIt(): void
    {
        $gone = $this->makeConnection(['tenant_id' => 'tenant-2']);

        $this->key(40 * self::DAY, KeyUse::CLIENT_ASSERTION, KeyState::CURRENT, connection: $gone);

        $kept = $this->key(41 * self::DAY);

        $gone->delete();

        $listed = [];
        $run    = $this->report()->report(Clients::browser(), 60, static function (ExpiringKey $entry) use (&$listed): void {
            $listed[] = $entry->key->id;
        });

        self::assertSame([$kept->id], $listed);
        self::assertSame(1, $run->listed);
        self::assertSame(1, $run->count(ExpiryNotice::NOT_DUE));
        self::assertSame([], $this->reportedKeyIds());
    }

    /**
     * With no key to look at, a run reads one page and nothing else.
     *
     * @return void
     */
    public function testWithNoKeysReadsOnePageAlone(): void
    {
        $statements = $this->statementsOf(fn (): ExpiryRun => $this->report()->report(Clients::browser()));

        self::assertSame(['select'], array_map(static fn (array $statement): string => $statement['verb'], $statements));
    }

    /**
     * A key that has reached no threshold takes no lock and writes nothing: the
     * run reads the page and its connections alone.
     *
     * @return void
     */
    public function testAKeyThatHasReachedNoThresholdTakesNoLock(): void
    {
        $this->key(40 * self::DAY);

        $run        = null;
        $statements = $this->statementsOf(function () use (&$run): void {
            $run = $this->report()->report(Clients::browser(), 60);
        });

        self::assertSame(['select', 'select'], array_map(static fn (array $statement): string => $statement['verb'], $statements));
        self::assertInstanceOf(ExpiryRun::class, $run);
        self::assertSame(1, $run->count(ExpiryNotice::NOT_DUE));
        self::assertSame([], $this->reportedKeyIds());
    }

    /**
     * A page's connections are read in one query naming each connection once,
     * in the order its first key is read.
     *
     * @return void
     */
    public function testReadsEachConnectionOfAPageOnce(): void
    {
        $other = $this->makeConnection(['tenant_id' => 'tenant-2']);

        $this->key(self::DAY);
        $this->key(2 * self::DAY, KeyUse::CLIENT_ASSERTION, KeyState::CURRENT, connection: $other);
        $this->key(3 * self::DAY);
        $this->key(4 * self::DAY, KeyUse::CLIENT_ASSERTION, KeyState::CURRENT, connection: $other);

        $this->report()->report(Clients::browser());

        $statements = $this->statementsOf(fn (): ExpiryRun => $this->report()->report(Clients::browser()));

        self::assertCount(2, $statements);
        self::assertSame([$this->saml->id, $other->id], $statements[1]['bindings']);
    }

    /**
     * The report writes nothing but its marker: every other column of the keys,
     * and the connections, are as they were, and an expired certificate is
     * still trusted.
     *
     * @return void
     */
    public function testChangesNothingButTheMarker(): void
    {
        $this->key(-self::DAY);
        $this->key(self::DAY, KeyUse::SP_SIGNING, KeyState::CURRENT);
        $this->key(self::DAY, KeyUse::SP_SIGNING, KeyState::RETIRING, 0);

        $before = $this->rows();

        self::assertCount(2, $this->listed());

        $after = $this->rows();

        self::assertSame($before['connections'], $after['connections']);
        self::assertSame(self::withoutMarkers($before['keys']), self::withoutMarkers($after['keys']));
    }

    /**
     * Inside a transaction a report refuses, since a warning is dispatched
     * before it is recorded, and neither lists nor dispatches.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAnOpenTransaction(): void
    {
        $this->key(self::DAY);

        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        try {
            $this->report()->report(Clients::browser());
            self::fail('A report inside a transaction was accepted.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('An expiry report runs outside any transaction on the storage connection', $exception->getMessage());
        } finally {
            $database->rollBack();
        }

        $this->assertNoEvents();
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
            $listed = $this->listed();
        } finally {
            DB::connection(StorageConnection::name())->setReadPdo(null);
        }

        self::assertSame([$key->id], $listed);
    }

    /**
     * With the storage on a connection of its own and nothing on the default,
     * the key is listed, warned of and marked there, and every transaction of
     * the run, the claim's and the marker's, is opened there; a transaction
     * open there refuses the run.
     *
     * @return void
     */
    public function testRunsOnAStorageConnectionOfItsOwn(): void
    {
        config()->set('database.connections.store', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);

        $this->withTablesUnder(['sso.storage.connection' => 'store'], function (): void {

            $key   = $this->key(self::DAY)->id;
            $began = [];

            Event::listen(TransactionBeginning::class, static function (TransactionBeginning $event) use (&$began): void {
                $began[] = $event->connectionName;
            });

            $this->assertWarnedAndMarked($key);

            self::assertSame(['store'], array_values(array_unique($began)));
            self::assertFalse(Schema::hasTable('sso_keys'));

            $database = DB::connection('store');

            $database->beginTransaction();

            try {
                $this->report()->report(Clients::browser());
                self::fail('A report ran inside a transaction.');
            } catch (\LogicException $exception) {
                self::assertStringContainsString('transaction', $exception->getMessage());
            } finally {
                $database->rollBack();
            }
        });
    }

    /**
     * Renamed tables are listed from, warned of and marked under their names.
     *
     * @return void
     */
    public function testRunsOnRenamedTables(): void
    {
        $this->withTablesUnder(['sso.keys.table' => 'renamed_keys', 'sso.connections.table' => 'renamed_connections'], function (): void {

            $key = $this->key(self::DAY)->id;

            $this->assertWarnedAndMarked($key);

            self::assertSame(1, DB::connection(StorageConnection::name())->table('renamed_keys')->where('id', $key)->whereNotNull('expiry_notified_at')->count());
            self::assertFalse(Schema::hasTable('sso_keys'));
        });
    }

    /**
     * A schema-qualified table is listed from, warned of and marked where it
     * lives.
     *
     * @return void
     */
    public function testRunsOnASchemaQualifiedTable(): void
    {
        $database = DB::connection(StorageConnection::name());
        $driver   = $database->getDriverName();
        $schema   = 'sso_report_schema';

        match ($driver) {
            'sqlite' => $database->statement("attach database ':memory:' as {$schema}"),
            'pgsql'  => $database->statement("create schema {$schema}"),
            default  => $database->statement("create database {$schema}"),
        };

        try {

            $this->withTablesUnder(['sso.keys.table' => "{$schema}.sso_keys"], function () use ($database, $schema): void {

                $key = $this->key(self::DAY)->id;

                $this->assertWarnedAndMarked($key);

                self::assertSame(1, $database->table("{$schema}.sso_keys")->where('id', $key)->whereNotNull('expiry_notified_at')->count());
                self::assertFalse(Schema::hasTable('sso_keys'));
            });
        } finally {

            match ($driver) {
                'sqlite' => $database->statement("detach database {$schema}"),
                'pgsql'  => $database->statement("drop schema {$schema} cascade"),
                default  => $database->statement("drop database {$schema}"),
            };
        }
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
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDaysOutOfRange')]
    public function testRefusesADayCountOutOfRange(int $days): void
    {
        $this->key(-self::DAY);

        try {
            $this->report()->report(Clients::browser(), $days);
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

        self::assertSame([], $this->listed(1));
        self::assertSame([$key->id], $this->listed(365));
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
     * Run the test with the connections table and the keys and certificates
     * table made afresh under the settings, on the new connection they name
     * when one does, and dropped again however it ends.
     *
     * @param  array<string, string>  $settings
     * @param  \Closure(): void  $test
     * @return void
     */
    private function withTablesUnder(array $settings, \Closure $test): void
    {
        $this->migrateConnectionTables(false);

        config()->set($settings);

        $this->migrateConnectionTables(true);

        try {

            $this->saml = $this->makeConnection(['protocol' => 'saml2']);

            $test();
        } finally {
            $this->migrateConnectionTables(false);
        }
    }

    /**
     * Run the shipped migrations of the connections table and the keys and
     * certificates table up, in order, or down, in reverse, under the settings
     * as they stand.
     *
     * @param  bool  $up
     * @return void
     */
    private function migrateConnectionTables(bool $up): void
    {
        $files = ['2026_11_01_000000_create_sso_connections_table.php', '2026_11_01_000001_create_sso_keys_table.php'];

        foreach ($up ? $files : array_reverse($files) as $file) {

            $migration = require dirname(__DIR__, 3) . '/database/migrations/' . $file;

            self::assertInstanceOf(Migration::class, $migration);

            if ($up) {
                $migration->up(); // @phpstan-ignore method.notFound
            } else {
                $migration->down(); // @phpstan-ignore method.notFound
            }
        }
    }

    /**
     * Assert a run lists and warns of the key, and stores its marker with no
     * claim left, wherever the keys are.
     *
     * @param  string  $key
     * @return void
     */
    private function assertWarnedAndMarked(string $key): void
    {
        self::assertSame([$key], $this->listed());
        self::assertSame([$key], $this->reportedKeyIds());

        $stored = ConnectionKey::query()->whereKey($key)->sole();

        self::assertSame(1, $stored->expiry_notified_threshold);
        self::assertSame(self::NOW, $stored->expiry_notified_at?->format('Y-m-d\TH:i:s\Z'));
        self::assertNull($stored->expiry_claimed_until);
    }

    /**
     * The statements the storage connection ran from the action on, each by its
     * first word, lower case, and its bindings.
     *
     * @param  \Closure(): mixed  $action
     * @return list<array{verb: string, bindings: array<array-key, mixed>}>
     */
    private function statementsOf(\Closure $action): array
    {
        $statements = [];

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = ['verb' => strtolower(substr($query->sql, 0, 6)), 'bindings' => $query->bindings];
        });

        $action();

        return $statements;
    }

    /**
     * The entries of a run looking the days given ahead, in order.
     *
     * @param  ?int  $days
     * @return list<\SineMacula\Laravel\Sso\Keys\ExpiringKey>
     */
    private function entries(?int $days = null): array
    {
        $entries = [];

        $this->report()->report(Clients::browser(), $days, static function (ExpiringKey $entry) use (&$entries): void {
            $entries[] = $entry;
        });

        return $entries;
    }

    /**
     * The ids of the keys a run looking the days given ahead lists, in order.
     *
     * @param  ?int  $days
     * @return list<string>
     */
    private function listed(?int $days = null): array
    {
        return array_map(static fn (ExpiringKey $entry): string => $entry->key->id, $this->entries($days));
    }

    /**
     * The notice of each key a run lists, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice>
     */
    private function notices(): array
    {
        return array_map(static fn (ExpiringKey $entry): ExpiryNotice => $entry->notice, $this->entries());
    }

    /**
     * The rows without the columns the report writes.
     *
     * @param  list<array<array-key, mixed>>  $rows
     * @return list<array<array-key, mixed>>
     */
    private static function withoutMarkers(array $rows): array
    {
        return array_map(static function (array $row): array {

            unset($row['expiry_notified_threshold'], $row['expiry_notified_at'], $row['expiry_claimed_until']);

            return $row;
        }, $rows);
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
