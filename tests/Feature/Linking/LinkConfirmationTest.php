<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\LinkConfirmed;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\LinkBranch;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;
use SineMacula\Laravel\Sso\Linking\IdentityLock;
use SineMacula\Laravel\Sso\Linking\LinkConfirmationGate;
use SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\IdentityGuard;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\ComparesIdentitiesWithoutCase;
use Tests\Concerns\RecordsLockOrder;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Adversarial tests of who may confirm a link of verified domain provenance
 * (SSO-8.8, SSO-8.5). An identity provider that captured a person by a verified
 * domain can sign that person in, and so can answer a `link` of them with the
 * same subject: that must not count as the person's confirmation, or it clears
 * the provenance and the link escapes the principal scope rule for good. Nor
 * may it add a second subject, in that connection or another, with no such
 * provenance.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkConfirmationGate::class)]
#[CoversClass(LinkBranch::class)]
#[CoversClass(IdentityLock::class)]
#[CoversClass(HandoffRedemption::class)]
final class LinkConfirmationTest extends LinkingTestCase
{
    use ComparesIdentitiesWithoutCase, RecordsLockOrder;

    /** @var string Another subject of the same provider. */
    private const string SECOND_SUBJECT = 'second-subject';

    /** @var string The session the person redeems on. */
    private const string REDEEMER_SESSION = 'session-of-the-redeemer';

    /** @var int How many rows a test has made of its own, each of its own subject. */
    private int $rows = 0;

    /**
     * Bind a fresh caller and an eligibility that lets every identity link: all
     * that stands between a captured session and a confirmation is the contract
     * these tests are about.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
    }

    /**
     * Under the package's default, a session established through the domain
     * link cannot clear its provenance: the `link` is refused, the row is left
     * exactly as it was, no `LinkConfirmed` is reported, and a later widening
     * still finds the link and suspends it.
     *
     * @return void
     */
    public function testUnderTheDefaultTheProviderCannotConfirmItsOwnLink(): void
    {
        $this->app?->instance(LinkConfirmation::class, new RefusingLinkConfirmation);

        $link   = $this->linkByDomain();
        $answer = $this->redeemLink();

        self::assertSame(FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED, $answer->reason);
        self::assertFalse($answer->isRedeemed());

        $kept = Link::query()->sole();

        self::assertSame($link->id, $kept->id);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $kept->provenance);
        self::assertTrue($kept->domain_provenance);
        self::assertSame(LinkState::ACTIVE, $kept->state);
        self::assertSame([], array_values(array_filter($this->recordedEvents(), static fn (object $event): bool => $event instanceof LinkConfirmed)));

        self::assertSame(1, $this->connection->getConnection()->transaction(fn (): int => app(ScopeWidening::class)->widened([$this->person], 'tenant-2', Clients::browser())));
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * The contract is asked about the identity's own domain links alone, as a
     * list, whatever an engine's collation also finds.
     *
     * @return void
     */
    public function testOnlyTheIdentitysOwnLinksAreNamed(): void
    {
        $this->compareIdentityIdsWithoutCase();

        $person = new IdentityReference($this->person->type, 'ada');

        $this->makeLink($this->connection, 'subject-of-another-person', [
            'id'            => '00000000000000000000000000',
            'issuer'        => VerifyingDriver::ISSUER,
            'identity_type' => $person->type,
            'identity_id'   => 'ADA',
            'provenance'    => LinkOrigin::VERIFIED_DOMAIN,
        ]);

        $own = $this->makeLink($this->connection, 'subject-of-this-person', [
            'issuer'        => VerifyingDriver::ISSUER,
            'identity_type' => $person->type,
            'identity_id'   => $person->id,
            'provenance'    => LinkOrigin::VERIFIED_DOMAIN,
        ]);

        $held = $this->connection->getConnection()->transaction(function () use ($person): array {
            $lock = app(HandoffRecheck::class)->lock('tenant-1', $this->connection->id, 'web', null, $person);

            return app(LinkConfirmationGate::class)->lockedDomainLinks($person, $lock);
        });

        self::assertSame([$own->id], $held);
        self::assertSame([$this->connection->id], LinkConfirmationGate::connectionsHolding($person));
        self::assertTrue(app(LinkConfirmationGate::class)->allows(new Caller($person, self::REDEEMER_SESSION), $this->connection, $held, false));
        self::assertSame([[$person->id, $this->connection->id, [$own->id]]], $this->confirmation->asked);
    }

    /**
     * A suspended link is not confirmed by a session that survived it either.
     *
     * @return void
     */
    public function testASuspendedLinkStaysSuspendedWithoutIndependentAuthentication(): void
    {
        $link = $this->linkByDomain();

        $link->forceFill(['state' => LinkState::SUSPENDED, 'suspended_at' => $this->clock->now()])->save();

        $this->confirmation->verdict = LinkConfirmationVerdict::DEPENDENT;

        self::assertSame(FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED, $this->redeemLink()->reason);

        $kept = Link::query()->sole();

        self::assertSame(LinkState::SUSPENDED, $kept->state);
        self::assertNotNull($kept->suspended_at);
        self::assertTrue($kept->domain_provenance);
    }

    /**
     * Independent authentication confirms: the provenance and any suspension
     * are cleared. The contract is asked in the judgement and again in the
     * admission, for this identity and connection, naming exactly the link, and
     * each time it is given the caller the redemption was made for, with its
     * session, as given.
     *
     * @return void
     */
    public function testIndependentAuthenticationConfirms(): void
    {
        $link   = $this->linkByDomain();
        $caller = new Caller(new IdentityReference($this->person->type, $this->person->id), self::REDEEMER_SESSION);

        $link->forceFill(['state' => LinkState::SUSPENDED, 'suspended_at' => $this->clock->now()])->save();

        self::assertTrue($this->redeemLink($caller)->isRedeemed());
        self::assertSame([$caller, $caller], $this->confirmation->callers);

        $kept = Link::query()->sole();

        self::assertSame(LinkOrigin::LINK_PURPOSE, $kept->provenance);
        self::assertSame(LinkState::ACTIVE, $kept->state);
        self::assertNull($kept->suspended_at);
        self::assertSame([
            [$this->person->id, $this->connection->id, [$link->id]],
            [$this->person->id, $this->connection->id, [$link->id]],
        ], $this->confirmation->asked);
    }

    /**
     * A verdict that turned between the judgement and the admission is refused
     * by the admission, which writes nothing.
     *
     * @return void
     */
    public function testTheAdmissionJudgesAgain(): void
    {
        $this->linkByDomain();

        $this->confirmation->queued = [LinkConfirmationVerdict::INDEPENDENT, LinkConfirmationVerdict::DEPENDENT];

        self::assertSame(FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED, $this->redeemLink()->reason);
        self::assertCount(2, $this->confirmation->asked);
        self::assertTrue(Link::query()->sole()->domain_provenance);
    }

    /**
     * With a limit above one, the captured session cannot add a second subject,
     * which would stand with no domain provenance and so escape the rule.
     *
     * @return void
     */
    public function testASecondSubjectIsNotAddedWithoutIndependentAuthentication(): void
    {
        $this->allowLinks(2);

        $first = $this->linkByDomain();

        $this->confirmation->verdict = LinkConfirmationVerdict::DEPENDENT;
        $this->verifying->claims     = self::claimsOf(self::SECOND_SUBJECT);

        self::assertSame(FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED, $this->redeemLink()->reason);
        self::assertSame($first->id, Link::query()->sole()->id);
    }

    /**
     * The same rule holds through another connection, which the same tenant's
     * administrator may have pointed at the same provider.
     *
     * @return void
     */
    public function testASubjectIsNotAddedThroughAnotherConnectionWithoutIndependentAuthentication(): void
    {
        $this->allowLinks(2);

        $first = $this->linkByDomain();

        $this->connection = $this->anotherConnection();

        $this->confirmation->verdict = LinkConfirmationVerdict::DEPENDENT;
        $this->verifying->claims     = self::claimsOf(self::SECOND_SUBJECT);

        self::assertSame(FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED, $this->redeemLink()->reason);
        self::assertSame($first->id, Link::query()->sole()->id);
        self::assertSame([$this->person->id, $this->connection->id, [$first->id]], $this->confirmation->asked[0]);
    }

    /**
     * The identity's guard comes first, then every connection holding one of
     * its domain links with the redemption's own, in one locking statement,
     * then the code and the links; and every application contract is asked only
     * then, so its guards come after the package's.
     *
     * @return void
     */
    public function testAllThePackagesLocksComeBeforeAnyApplicationContract(): void
    {
        $this->allowLinks(2);

        $this->linkByDomain();

        $first  = $this->connection->id;
        $second = $this->anotherConnection();

        $this->connection        = $second;
        $this->verifying->claims = self::claimsOf(self::SECOND_SUBJECT);

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();
        $seen       = [];

        $this->app?->instance(LinkEligibility::class, new class ($seen, $this->lockOrder(...)) implements LinkEligibility {
            /**
             * Constructor.
             *
             * @param  list<list<string>>  $seen
             * @param  \Closure(): list<string>  $locks
             */
            public function __construct(

                /** What the locks were at each judgement. */
                public array &$seen,

                /** What the locks are. */
                private \Closure $locks,
            ) {}

            /**
             * Record the locks taken so far, and allow it.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict
             */
            #[\Override]
            public function judge(IdentityReference $identity, SsoConnection $connection): LinkEligibilityVerdict
            {
                unset($identity, $connection);

                $this->seen[] = ($this->locks)();

                return LinkEligibilityVerdict::ELIGIBLE;
            }
        });

        $this->recordLockOrder();

        self::assertTrue($this->admit($completion, $start, Purpose::LINK, $this->person)->isRedeemed());

        $ids = [$first, $second->id];

        sort($ids, SORT_STRING);

        self::assertSame(['identity guard', 'identity mark', 'connections ' . implode(', ', $ids), 'code', 'link', 'link'], $seen[0]);
    }

    /**
     * A domain link in a connection the plain read did not find stands in a
     * connection that was not locked, and cannot be locked now: the redemption
     * throws for a retry of the whole transaction, with nothing written and the
     * code unspent. The retry reaches it, and asks the contract.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkInAConnectionThePlainReadMissedRefusesTheWholeRedemption(): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();
        $other      = $this->anotherConnection();
        $inserted   = false;

        $provenance = $this->connection->getConnection()->getQueryGrammar()->wrap('provenance');

        $this->connection->getConnection()->listen(function (QueryExecuted $query) use ($other, $provenance, &$inserted): void {

            if ($inserted || !str_contains($query->sql, $provenance) || !str_starts_with(strtolower($query->sql), 'select')) {
                return;
            }

            $inserted = true;

            $this->makeLink($other, 'a-subject-held-elsewhere', [
                'identity_type' => $this->person->type,
                'identity_id'   => $this->person->id,
                'issuer'        => VerifyingDriver::ISSUER,
                'provenance'    => LinkOrigin::VERIFIED_DOMAIN,
            ]);
        });

        try {
            $this->connection->getConnection()->transaction(fn (): RedemptionResult => $this->admit($completion, $start, Purpose::LINK, $this->person));
            self::fail('The redemption went on over a link it did not lock.');
        } catch (LinkCandidatesChanged $exception) {
            self::assertSame('An identity\'s verified domain links changed before they were locked; retry the whole transaction.', $exception->getMessage());
        }

        self::assertSame(0, Link::query()->count(), 'What that transaction made rolls back with it.');
        self::assertNull(HandoffCode::query()->sole()->redeemed_at);
        self::assertSame([], $this->confirmation->asked);
    }

    /**
     * Removing one domain link, through the link service, does not make the
     * session that survives it independent, nor touch the identity's other
     * domain link: a contract that answers from the links it is given, and
     * would pass a caller holding none, is asked about exactly the one left,
     * and refuses.
     *
     * @return void
     */
    public function testRemovingALinkDoesNotConfirmTheOtherLinksOfTheIdentity(): void
    {
        $this->allowLinks(3);

        $first = $this->linkByDomain();
        $held  = $this->heldRow(LinkOrigin::VERIFIED_DOMAIN, LinkState::ACTIVE);

        $this->confirmation->fromLinks = static fn (array $ids): LinkConfirmationVerdict => $ids === [] ? LinkConfirmationVerdict::INDEPENDENT : LinkConfirmationVerdict::DEPENDENT;

        self::assertTrue(app(LinkService::class)->remove($this->person, $first->id, Clients::browser())->isRemoved());

        $this->verifying->claims = self::claimsOf(self::SECOND_SUBJECT);

        self::assertSame(FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED, $this->redeemLink()->reason);
        self::assertSame([[$this->person->id, $this->connection->id, [$held->id]]], $this->confirmation->asked);

        $kept = Link::query()->sole();

        self::assertSame([$held->id, LinkOrigin::VERIFIED_DOMAIN, LinkState::ACTIVE], [$kept->id, $kept->provenance, $kept->state]);
    }

    /**
     * Rows of `[whether the identity holds a provisioned link of the second
     * subject]`: without it the `link` would create that subject's link, and
     * with it, confirm the one held.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideLinksAfterARemoval(): iterable
    {
        yield 'creating a second subject' => [false];
        yield 'confirming a subject held' => [true];
    }

    /**
     * Once the identity's only domain link is removed, through the link
     * service, the session that survived it still cannot link: the guard
     * remembers that the identity held one, so the contract is asked, with no
     * link left to name, and refuses; nothing is written and the code is spent.
     *
     * @param  bool  $provisioned
     * @return void
     */
    #[DataProvider('provideLinksAfterARemoval')]
    public function testRemovingTheOnlyDomainLinkStillNeedsIndependentAuthentication(bool $provisioned): void
    {
        $this->allowLinks(3);

        $first = $this->linkByDomain();
        $kept  = $provisioned ? $this->makeLink($this->connection, self::SECOND_SUBJECT, [
            'issuer'        => VerifyingDriver::ISSUER,
            'identity_type' => $this->person->type,
            'identity_id'   => $this->person->id,
            'provenance'    => LinkOrigin::PROVISIONING,
        ]) : null;

        $this->confirmation->verdict = LinkConfirmationVerdict::DEPENDENT;

        self::assertTrue(app(LinkService::class)->remove($this->person, $first->id, Clients::browser())->isRemoved());
        self::assertNotNull(IdentityGuard::query()->where('identity_hash', IdentityLock::digest($this->person))->sole()->domain_linked_at);

        $this->verifying->claims = self::claimsOf(self::SECOND_SUBJECT);

        $answer = $this->redeemLink();

        self::assertSame(FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED, $answer->reason);
        self::assertSame([[$this->person->id, $this->connection->id, []]], $this->confirmation->asked);
        self::assertSame($provisioned ? [$kept?->id] : [], Link::query()->pluck('id')->all());
        self::assertSame($provisioned ? LinkOrigin::PROVISIONING : null, $kept === null ? null : Link::query()->sole()->provenance);
        self::assertSame([], array_values(array_filter($this->recordedEvents(), static fn (object $event): bool => $event instanceof LinkConfirmed)));
    }

    /**
     * Removed and then linked again by the domain, the identity is asked about
     * the new link alone, and a contract that independent authentication passes
     * lets it confirm; the guard's mark is the first activation's.
     *
     * @return void
     */
    public function testRemovedAndLinkedAgainByTheDomain(): void
    {
        $first  = $this->linkByDomain();
        $marked = IdentityGuard::query()->sole()->domain_linked_at?->toIso8601String();

        self::assertTrue(app(LinkService::class)->remove($this->person, $first->id, Clients::browser())->isRemoved());

        $this->clock->advance(60);

        $again = $this->linkByDomain();

        self::assertNotSame($first->id, $again->id);
        self::assertSame($marked, IdentityGuard::query()->sole()->domain_linked_at?->toIso8601String());

        $this->confirmation->verdict = LinkConfirmationVerdict::DEPENDENT;

        self::assertSame(FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED, $this->redeemLink()->reason);
        self::assertSame([[$this->person->id, $this->connection->id, [$again->id]]], $this->confirmation->asked);

        $this->confirmation->verdict = LinkConfirmationVerdict::INDEPENDENT;

        self::assertTrue($this->redeemLink()->isRedeemed());
        self::assertSame(LinkOrigin::LINK_PURPOSE, Link::query()->sole()->provenance);
    }

    /**
     * An identity that has never held an active domain link is never asked
     * about, and its guard is never marked: a reservation alone marks nothing.
     *
     * @return void
     */
    public function testAReservationAloneMarksNothing(): void
    {
        $this->start();
        $this->complete();

        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
        self::assertNull(IdentityGuard::query()->sole()->domain_linked_at);
    }

    /**
     * A standalone `link` takes the identity's guard before any read in its
     * transaction: the connection's tenant is read before it opens, so the
     * guard's upsert is its first statement.
     *
     * @return void
     */
    public function testAStandaloneLinkTakesTheGuardBeforeAnyRead(): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();
        $sequence   = [];
        $database   = DB::connection(StorageConnection::name());

        $database->listen(static function (QueryExecuted $query) use (&$sequence): void {
            $sequence[] = strtolower($query->sql);
        });

        $database->getEventDispatcher()?->listen(TransactionBeginning::class, static function () use (&$sequence): void {
            $sequence[] = 'begin';
        });

        self::assertSame(0, $database->transactionLevel());
        self::assertTrue($this->redeemStandalone($completion->handoff?->code->reveal(), $start->verifier?->reveal())->isRedeemed());

        $begin = (int) array_search('begin', $sequence, true);

        self::assertMatchesRegularExpression('/^select ["`]?tenant_id["`]? from/', $sequence[$begin - 1]);
        self::assertStringStartsWith('insert into ' . $database->getQueryGrammar()->wrapTable(StorageConnection::table('identity_guards.table')), $sequence[$begin + 1]);
    }

    /**
     * A standalone `link` that comes to a domain link in a connection it did
     * not lock is rolled back and restarted once, from its transaction, and
     * then redeems: what the first attempt saw rolls back with it.
     *
     * @return void
     */
    public function testAStandaloneLinkRestartsOnceWhenItsCandidatesChanged(): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();
        $other      = $this->anotherConnection();
        $inserted   = false;
        $guards     = 0;

        $grammar    = $this->connection->getConnection()->getQueryGrammar();
        $guardTable = 'insert into ' . $grammar->wrapTable(StorageConnection::table('identity_guards.table'));
        $provenance = $grammar->wrap('provenance');

        $this->connection->getConnection()->listen(function (QueryExecuted $query) use ($other, $guardTable, $provenance, &$inserted, &$guards): void {

            $sql = strtolower($query->sql);

            if (str_starts_with($sql, $guardTable)) {
                $guards++;
            }

            if ($inserted || !str_contains($sql, $provenance) || !str_starts_with($sql, 'select')) {
                return;
            }

            $inserted = true;

            $this->makeLink($other, 'a-subject-held-elsewhere', [
                'identity_type' => $this->person->type,
                'identity_id'   => $this->person->id,
                'issuer'        => VerifyingDriver::ISSUER,
                'provenance'    => LinkOrigin::VERIFIED_DOMAIN,
            ]);
        });

        $answer = $this->redeemStandalone($completion->handoff?->code->reveal(), $start->verifier?->reveal());

        self::assertTrue($answer->isRedeemed());
        self::assertFalse($answer->isAdmitted());
        self::assertSame(2, $guards);
        self::assertSame(LinkOrigin::LINK_PURPOSE, Link::query()->sole()->provenance);
        self::assertNotNull(HandoffCode::query()->sole()->redeemed_at);
        self::assertSame([], $this->confirmation->asked);
    }

    /**
     * A standalone `link` whose candidates change again in its restart
     * propagates `LinkCandidatesChanged`: it restarts once, never twice, and
     * leaves nothing written and the code unspent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStandaloneLinkRestartsOnlyOnce(): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();
        $other      = $this->anotherConnection();
        $inserted   = 0;
        $guards     = 0;

        $grammar    = $this->connection->getConnection()->getQueryGrammar();
        $guardTable = 'insert into ' . $grammar->wrapTable(StorageConnection::table('identity_guards.table'));
        $provenance = $grammar->wrap('provenance');

        $this->connection->getConnection()->listen(function (QueryExecuted $query) use ($other, $guardTable, $provenance, &$inserted, &$guards): void {

            $sql = strtolower($query->sql);

            if (str_starts_with($sql, $guardTable)) {
                $guards++;
            }

            if ($inserted === $guards || !str_contains($sql, $provenance) || !str_starts_with($sql, 'select')) {
                return;
            }

            $inserted++;

            $this->makeLink($other, 'a-subject-held-elsewhere', [
                'identity_type' => $this->person->type,
                'identity_id'   => $this->person->id,
                'issuer'        => VerifyingDriver::ISSUER,
                'provenance'    => LinkOrigin::VERIFIED_DOMAIN,
            ]);
        });

        $redemption = app(HandoffRedemption::class);
        $code       = (string) $completion->handoff?->code->reveal();
        $verifier   = (string) $start->verifier?->reveal();

        try {
            $redemption->redeem(Purpose::LINK, 'web', $this->connection->id, $code, $verifier, Clients::browser(), new Caller($this->person));
            self::fail('A standalone link restarted more than once.');
        } catch (LinkCandidatesChanged) {
            self::assertSame(2, $guards);
        }

        self::assertSame(0, Link::query()->count());
        self::assertNull(HandoffCode::query()->sole()->redeemed_at);
        self::assertSame(0, $this->connection->getConnection()->transactionLevel());
    }

    /**
     * With independent authentication a second subject is made, with no domain
     * provenance; every domain link is named, in id order, active and suspended
     * alike.
     *
     * @return void
     */
    public function testIndependentAuthenticationAddsASubject(): void
    {
        $this->allowLinks(3);

        $first  = $this->linkByDomain();
        $second = $this->heldRow(LinkOrigin::VERIFIED_DOMAIN, LinkState::SUSPENDED);

        $this->verifying->claims = self::claimsOf(self::SECOND_SUBJECT);

        self::assertTrue($this->redeemLink()->isRedeemed());

        $ids = [$first->id, $second->id];

        sort($ids);

        self::assertSame([$this->person->id, $this->connection->id, $ids], $this->confirmation->asked[0]);
        self::assertSame(LinkOrigin::LINK_PURPOSE, Link::query()->where('subject', self::SECOND_SUBJECT)->sole()->provenance);
    }

    /**
     * Rows of `[what the identity holds, whether a row of that kind asks]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin, 1: \SineMacula\Laravel\Sso\Links\Enums\LinkState, 2: bool}>
     */
    public static function provideHeldRows(): iterable
    {
        yield 'an active domain link' => [LinkOrigin::VERIFIED_DOMAIN, LinkState::ACTIVE, true];
        yield 'a suspended domain link' => [LinkOrigin::VERIFIED_DOMAIN, LinkState::SUSPENDED, true];
        yield 'a reservation, on which no session stands' => [LinkOrigin::VERIFIED_DOMAIN, LinkState::RESERVED, false];
        yield 'a confirmed link' => [LinkOrigin::LINK_PURPOSE, LinkState::ACTIVE, false];
        yield 'a provisioned link' => [LinkOrigin::PROVISIONING, LinkState::ACTIVE, false];
        yield 'a migrated link' => [LinkOrigin::MIGRATION, LinkState::ACTIVE, false];
    }

    /**
     * The contract is asked only for what stands on a verified domain, and only
     * what it is asked about is named; refused, it refuses, and otherwise the
     * `link` goes on unasked.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @param  bool  $asks
     * @return void
     */
    #[DataProvider('provideHeldRows')]
    public function testWhatTheIdentityHoldsDecidesWhetherItIsAsked(LinkOrigin $origin, LinkState $state, bool $asks): void
    {
        $this->allowLinks(3);

        $held = $this->heldRow($origin, $state);

        $this->confirmation->verdict = LinkConfirmationVerdict::DEPENDENT;

        $answer = $this->redeemLink();

        self::assertSame($asks ? FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED : null, $answer->reason);
        self::assertSame($asks ? [[$this->person->id, $this->connection->id, [$held->id]]] : [], $this->confirmation->asked);
    }

    /**
     * Another identity's domain link, in this connection or another, asks
     * nothing of this caller.
     *
     * @return void
     */
    public function testAnotherIdentitysDomainLinkAsksNothing(): void
    {
        $this->heldRow(LinkOrigin::VERIFIED_DOMAIN, LinkState::ACTIVE, 'someone-else');
        $this->heldRow(LinkOrigin::VERIFIED_DOMAIN, LinkState::ACTIVE, null, 'of-another-type');

        $this->confirmation->verdict = LinkConfirmationVerdict::DEPENDENT;

        self::assertTrue($this->redeemLink()->isRedeemed());
        self::assertSame([], $this->confirmation->asked);
    }

    /**
     * The contract's exception propagates and rolls everything back: the code
     * is not spent, the link is unchanged, and the redemption retried stands.
     *
     * @return void
     */
    public function testTheContractsExceptionRollsTheRedemptionBack(): void
    {
        $this->linkByDomain();

        $failure = new \RuntimeException('The session store is down.');

        $this->confirmation->failure = $failure;

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        try {
            $this->admit($completion, $start, Purpose::LINK, $this->person);

            self::fail('The redemption went on.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertNull(HandoffCode::query()->latest('id')->firstOrFail()->redeemed_at);
        self::assertTrue(Link::query()->sole()->domain_provenance);

        $this->confirmation->failure = null;

        self::assertTrue($this->admit($completion, $start, Purpose::LINK, $this->person)->isRedeemed());
        self::assertFalse(Link::query()->sole()->domain_provenance);
    }

    /**
     * Make the active link of the driver's subject, through a reservation and
     * its redemption.
     *
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function linkByDomain(): Link
    {
        $start = $this->start();

        self::assertTrue($this->admit($this->complete(), $start)->isRedeemed());

        return Link::query()->sole();
    }

    /**
     * Redeem the `link` code standalone, with no transaction open, as the
     * person.
     *
     * @param  ?string  $code
     * @param  ?string  $verifier
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeemStandalone(?string $code, ?string $verifier): RedemptionResult
    {
        return app(HandoffRedemption::class)->redeem(
            Purpose::LINK,
            'web',
            $this->connection->id,
            (string) $code,
            (string) $verifier,
            Clients::browser(),
            new Caller($this->person),
        );
    }

    /**
     * Run a `link` flow for the person, through to its redemption by the caller
     * given, or the person on the redeemer's session.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeemLink(?Caller $caller = null): RedemptionResult
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted(), (string) $completion->reason?->value);

        return $this->admit($completion, $start, Purpose::LINK, $caller ?? new Caller($this->person, self::REDEEMER_SESSION));
    }

    /**
     * What the driver verifies for the subject, with no linking email.
     *
     * @param  string  $subject
     * @return \SineMacula\Laravel\Sso\Results\VerifiedClaims
     */
    private static function claimsOf(string $subject): VerifiedClaims
    {
        return new VerifiedClaims(VerifyingDriver::ISSUER, $subject, null, [], new AuthenticationContext);
    }

    /**
     * Let the identity hold this many links.
     *
     * @param  int  $limit
     * @return void
     */
    private function allowLinks(int $limit): void
    {
        $this->app?->instance(LinkLimit::class, new readonly class ($limit) implements LinkLimit {
            /**
             * Constructor.
             *
             * @param  int  $limit
             */
            public function __construct(

                /** What it answers. */
                private int $limit,
            ) {}

            /**
             * The limit given.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return int
             */
            #[\Override]
            public function maxLinks(IdentityReference $identity, SsoConnection $connection): int
            {
                unset($identity, $connection);

                return $this->limit;
            }
        });
    }

    /**
     * A second usable connection of the tenant, over the same provider.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function anotherConnection(): Connection
    {
        return $this->makeConnection([
            'protocol' => VerifyingDriver::NAME,
            'enabled'  => true,
            'settings' => ['issuer' => VerifyingDriver::ISSUER],
        ]);
    }

    /**
     * A row of another subject, held by the person unless told otherwise, of
     * the provenance and state, in this connection.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @param  ?string  $identityId
     * @param  ?string  $identityType
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function heldRow(LinkOrigin $origin, LinkState $state, ?string $identityId = null, ?string $identityType = null): Link
    {
        $this->rows++;

        return $this->makeLink($this->connection, 'held-subject-' . $this->rows, [
            'identity_type'          => $identityType ?? $this->person->type,
            'identity_id'            => $identityId   ?? $this->person->id,
            'issuer'                 => VerifyingDriver::ISSUER,
            'state'                  => $state,
            'provenance'             => $origin,
            'reservation_id'         => $state === LinkState::RESERVED ? 'reservation-' . $this->rows : null,
            'reservation_expires_at' => $state === LinkState::RESERVED ? $this->clock->now()->addMinute() : null,
        ]);
    }
}
