<?php

declare(strict_types = 1);

namespace Tests\Integration\Combined;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\SignInBranch;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RaceFlows;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Keys\Certificates;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Races a `sign_in` redemption of a code that resolved to a link, across
 * processes, each with its own database connection, on PostgreSQL and MySQL
 * (SSO-8.4, SSO-9.2, SSO-9.9), against what the suites of each change leave
 * out: a protocol trust change, the link's removal and its reassignment to
 * another identity, each in both winning orders.
 *
 * The racer going first holds the connection's lock in a transaction, signals,
 * and commits only once the database shows the other waiting on it, so the two
 * really overlap. The session a redeemer writes is a row of this test's on the
 * storage connection, committed with the consumption, and a revocation marks
 * it, so what these races protect is what is asserted: a session written before
 * a removal is found and revoked by it, and none is written after one.
 *
 * Each racer runs plainly, and inside its own `REPEATABLE READ` transaction
 * that read first. On MySQL its locking reads must then answer what is
 * committed and not its snapshot; on PostgreSQL the racer going second fails to
 * serialise, on the connection's row the first wrote, which is accepted there
 * alone and leaves nothing of it.
 *
 * Skipped on SQLite and without `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(SignInBranch::class)]
#[CoversClass(LinkService::class)]
#[CoversClass(LinkStore::class)]
#[CoversClass(KeyService::class)]
#[CoversClass(InFlightVoider::class)]
final class RedemptionRacesTest extends LinkingTestCase
{
    use RaceFlows;

    /** @var string The table the application keeps its sessions in. */
    private const string SESSIONS = 'combined_race_sessions';

    /** @var string A protocol trust change: a certificate no longer trusted. */
    private const string TRUST = 'trust';

    /** @var string The link's removal. */
    private const string UNLINK = 'unlink';

    /** @var string The link's reassignment to another identity. */
    private const string REASSIGN = 'reassign';

    /** @var string What a redemption that succeeded reports. */
    private const string REDEEMED = 'redeemed';

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity a reassignment moves the subject to. */
    private IdentityReference $other;

    /** @var \SineMacula\Laravel\Sso\Models\Link The link the code resolved to. */
    private Link $link;

    /** @var string The code raced for. */
    private string $code = '';

    /** @var string The code's verifier. */
    private string $verifier = '';

    /** @var string The certificate a trust change stops trusting. */
    private string $certificate = '';

    /**
     * Skip where processes cannot share the database; bind a fresh caller, a
     * limiter that allows every attempt and a revocation that marks the
     * identity's sessions; create the sessions' table; and make the link, a
     * trusted certificate, read before any process forks, and the completed
     * flow.
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

        $this->other = new IdentityReference('App\Models\User', '8');

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->allowEveryAttempt();
        $this->app?->instance(SessionRevocation::class, self::revocation());

        self::storageDatabase()->getSchemaBuilder()->create(self::SESSIONS, static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('identity_id');
            $table->string('connection_id');
            $table->string('link_id');
            $table->boolean('revoked')->default(false);
        });

        $this->certificate = $this->trustedCertificate();
        $this->link        = $this->heldLink();

        $start      = $this->start();
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        $this->code     = (string) $completion->handoff?->code->reveal();
        $this->verifier = (string) $start->verifier?->reveal();
    }

    /**
     * Remove what the race used and drop the sessions' table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->tearDownRace();

        self::storageDatabase()->getSchemaBuilder()->dropIfExists(self::SESSIONS);

        parent::tearDown();
    }

    /**
     * Rows of `[the change, whether the racer going first read first, whether
     * the racer going second did]`.
     *
     * @return iterable<string, array{0: string, 1: bool, 2: bool}>
     */
    public static function provideRaces(): iterable
    {
        foreach ([self::TRUST, self::UNLINK, self::REASSIGN] as $change) {
            yield "{$change}, both plainly" => [$change, false, false];
            yield "{$change}, the first in its own transaction that read first" => [$change, true, false];
            yield "{$change}, the second in its own transaction that read first" => [$change, false, true];
        }
    }

    /**
     * A redemption holding the connection's lock commits its session first. A
     * removal or a reassignment then finds that session and revokes it; a trust
     * change voids nothing of a code redeemed, and revokes nothing.
     *
     * @param  string  $change
     * @param  bool  $firstReads
     * @param  bool  $secondReads
     * @return void
     */
    #[DataProvider('provideRaces')]
    public function testARedemptionHoldingItsLocksThenTheChange(string $change, bool $firstReads, bool $secondReads): void
    {
        $reports = $this->race([
            fn (): array => $this->reported(fn (): string => $this->holdThenCommit(fn (): string => $this->redemption())),
            fn (): array => $this->reported(function () use ($change): string {

                $this->awaitSignal(self::HOLDS);

                $outcome = $this->changed($change);

                $this->commitSnapshot();

                return $outcome;
            }),
        ], null, $this->snapshotsFor([$firstReads, $secondReads], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertSame(['outcome' => self::REDEEMED, 'events' => [HandoffRedeemed::class]], $reports[0]['result']);

        $code = HandoffCode::query()->sole();

        self::assertNotNull($code->redeemed_at);
        self::assertNull($code->voided_at);
        self::assertSame(1, $this->sessions()->count());

        if (self::assertRacerEnded($reports[1], $secondReads)) {
            $this->assertNothingChanged();

            return;
        }

        self::assertSame($this->changeReported($change), $reports[1]['result']);

        $this->assertChangeStands($change, $change !== self::TRUST);
    }

    /**
     * The change holding the connection's lock commits first. The redemption
     * then finds its code voided by a trust change, `handoff_unknown` with the
     * code unconsumed, or its link gone or another identity's, `link_changed`
     * with the code spent. Either way no session is written.
     *
     * @param  string  $change
     * @param  bool  $firstReads
     * @param  bool  $secondReads
     * @return void
     */
    #[DataProvider('provideRaces')]
    public function testTheChangeHoldingItsLocksThenARedemption(string $change, bool $firstReads, bool $secondReads): void
    {
        $reports = $this->race([
            fn (): array => $this->reported(fn (): string => $this->holdThenCommit(fn (): string => $this->changed($change))),
            fn (): array => $this->reported(function (): string {

                $this->awaitSignal(self::HOLDS);

                $outcome = $this->redemption();

                $this->commitSnapshot();

                return $outcome;
            }),
        ], null, $this->snapshotsFor([$firstReads, $secondReads], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertSame($this->changeReported($change), $reports[0]['result']);
        self::assertSame(0, $this->sessions()->count());

        $this->assertChangeStands($change, false);

        $code = HandoffCode::query()->sole();

        if (self::assertRacerEnded($reports[1], $secondReads)) {
            self::assertNull($code->redeemed_at);

            return;
        }

        self::assertSame(['outcome' => 'refused:' . ($change === self::TRUST ? 'handoff_unknown' : 'link_changed'), 'events' => [FlowFailed::class]], $reports[1]['result']);

        self::assertSame($change !== self::TRUST, $code->redeemed_at !== null);
        self::assertSame($change === self::TRUST, $code->voided_at !== null);
    }

    /**
     * Assert the change committed: a trust change raised the connection's
     * version and removed the certificate; a removal left no link; a
     * reassignment left the subject the other identity's, under another link.
     * The session, when there is one, is revoked or not as given.
     *
     * @param  string  $change
     * @param  bool  $revoked
     * @return void
     *
     * @throws \LogicException
     */
    private function assertChangeStands(string $change, bool $revoked): void
    {
        match ($change) {
            self::TRUST    => $this->assertTrustChanged(),
            self::UNLINK   => self::assertSame(0, Link::query()->count()),
            self::REASSIGN => $this->assertReassigned(),
            default        => throw new \LogicException(sprintf('No change is named [%s].', $change)),
        };

        self::assertSame($revoked ? 1 : 0, $this->sessions()->where('revoked', true)->count());
    }

    /**
     * Assert a trust change committed, and the link stands.
     *
     * @return void
     */
    private function assertTrustChanged(): void
    {
        self::assertSame(1, Connection::query()->whereKey($this->connection->id)->sole()->trust_version);
        self::assertSame(0, ConnectionKey::query()->whereKey($this->certificate)->count());
        self::assertSame($this->link->id, Link::query()->sole()->id);
    }

    /**
     * Assert the subject is the other identity's, under another link.
     *
     * @return void
     */
    private function assertReassigned(): void
    {
        $link = Link::query()->sole();

        self::assertNotSame($this->link->id, $link->id);
        self::assertSame($this->other->id, $link->identity_id);
    }

    /**
     * Assert a change that failed to serialise left everything as it was, and
     * revoked nothing.
     *
     * @return void
     */
    private function assertNothingChanged(): void
    {
        self::assertSame(0, Connection::query()->whereKey($this->connection->id)->sole()->trust_version);
        self::assertSame(1, ConnectionKey::query()->whereKey($this->certificate)->count());
        self::assertSame($this->link->id, Link::query()->sole()->id);
        self::assertSame($this->person->id, Link::query()->sole()->identity_id);
        self::assertSame(0, $this->sessions()->where('revoked', true)->count());
    }

    /**
     * What a racer making the change reports.
     *
     * @param  string  $change
     * @return array{outcome: string, events: list<class-string>}
     *
     * @throws \LogicException
     */
    private function changeReported(string $change): array
    {
        return match ($change) {
            self::TRUST    => ['outcome' => 'distrusted', 'events' => [KeyRetired::class]],
            self::UNLINK   => ['outcome' => 'removed', 'events' => [LinkRemoved::class]],
            self::REASSIGN => ['outcome' => 'reassigned', 'events' => [LinkRemoved::class, LinkCreated::class]],
            default        => throw new \LogicException(sprintf('No change is named [%s].', $change)),
        };
    }

    /**
     * Run the racer, and report how it ended with the events it reported, once
     * whatever it committed has committed.
     *
     * @param  \Closure(): string  $racer
     * @return array{outcome: string, events: list<class-string>}
     */
    private function reported(\Closure $racer): array
    {
        $this->startRecordingEvents();

        $outcome = $racer();

        return ['outcome' => $outcome, 'events' => array_map(static fn (SsoEvent $event): string => $event::class, $this->recordedEvents())];
    }

    /**
     * Redeem the code in a transaction, a savepoint inside a snapshot, writing
     * the session in it when it is admitted, as a redeemer does.
     *
     * @return string
     */
    private function redemption(): string
    {
        $answer = self::storageDatabase()->transaction(function (): RedemptionResult {

            $answer = app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $this->code, $this->verifier);

            if ($answer->isRedeemed()) {
                $this->sessions()->insert([
                    'id'            => 'session-1',
                    'identity_id'   => (string) $answer->linkedIdentity?->id,
                    'connection_id' => $this->connection->id,
                    'link_id'       => (string) $answer->linkId,
                ]);
            }

            return $answer;
        });

        return $answer->isRedeemed() ? self::REDEEMED : 'refused:' . $answer->reason?->value;
    }

    /**
     * Make the change, and say how it ended.
     *
     * @param  string  $change
     * @return string
     *
     * @throws \LogicException
     */
    private function changed(string $change): string
    {
        return match ($change) {
            self::TRUST    => app(KeyService::class)->distrustCertificate('tenant-1', $this->connection->id, $this->certificate)->status->value,
            self::UNLINK   => $this->removal(),
            self::REASSIGN => $this->reassignment(),
            default        => throw new \LogicException(sprintf('No change is named [%s].', $change)),
        };
    }

    /**
     * Remove the link.
     *
     * @return string
     */
    private function removal(): string
    {
        $removal = app(LinkService::class)->remove($this->person, $this->link->id);

        return $removal->isRemoved() ? 'removed' : 'refused:' . $removal->reason?->value;
    }

    /**
     * Remove the link and link the subject to the other identity, in one
     * transaction of the application's.
     *
     * @return string
     */
    private function reassignment(): string
    {
        return self::storageDatabase()->transaction(function (): string {

            $removal = app(LinkService::class)->remove($this->person, $this->link->id);

            if (!$removal->isRemoved()) {
                return 'refused:' . $removal->reason?->value;
            }

            $subject  = new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT);
            $creation = app(LinkStore::class)->create($this->connection, $subject, $this->other, LinkOrigin::LINK_PURPOSE);

            return $creation->isCreated() ? 'reassigned' : 'refused:' . $creation->reason()?->value;
        });
    }

    /**
     * What a racer's snapshot reads.
     *
     * @return \Closure(): void
     */
    private function reads(): \Closure
    {
        return function (): void {
            Connection::query()->whereKey($this->connection->id)->get();
            Link::query()->where('connection_id', $this->connection->id)->get();
            HandoffCode::query()->where('connection_id', $this->connection->id)->get();
            ConnectionKey::query()->where('connection_id', $this->connection->id)->get();
            $this->sessions()->get();
        };
    }

    /**
     * Link the subject to the person, in this process.
     *
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function heldLink(): Link
    {
        $creation = app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT), $this->person, LinkOrigin::PROVISIONING);

        self::assertTrue($creation->isCreated());

        return Link::query()->whereKey($creation->link?->id)->sole();
    }

    /**
     * A certificate the connection trusts, its key read before any fork.
     *
     * @return string
     */
    private function trustedCertificate(): string
    {
        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $this->connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'public_key'    => (string) MaskedKey::fromCertificate(Certificates::distinct(50))->publicKey,
            'fingerprint'   => hash('sha256', 'the-trusted-certificate'),
            'not_after'     => CarbonImmutable::parse('2027-11-01T00:00:00Z'),
        ])->save();

        return $key->id;
    }

    /**
     * The sessions' table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function sessions(): Builder
    {
        return self::storageDatabase()->table(self::SESSIONS);
    }

    /**
     * A revocation that marks the identity's sessions through the connection,
     * in the change's transaction, as an adapter's does.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SessionRevocation
     */
    private static function revocation(): SessionRevocation
    {
        return new readonly class (self::SESSIONS) implements SessionRevocation {
            /**
             * Constructor.
             *
             * @param  string  $table
             */
            public function __construct(

                /** The sessions' table. */
                private string $table,
            ) {}

            /**
             * Mark the identity's sessions through the connection.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void
            {
                DB::connection(StorageConnection::name())->table($this->table)
                    ->where('connection_id', (string) $scope->connectionId)
                    ->where('identity_id', (string) $scope->identity?->id)
                    ->update(['revoked' => true]);
            }
        };
    }
}
