<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\LinkConfirmed;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\Redemption\LinkBranch;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;
use SineMacula\Laravel\Sso\Linking\LinkConfirmationGate;
use SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\ComparesIdentitiesWithoutCase;
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
final class LinkConfirmationTest extends LinkingTestCase
{
    use ComparesIdentitiesWithoutCase;

    /** @var string Another subject of the same provider. */
    private const string SECOND_SUBJECT = 'second-subject';

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

        self::assertSame(1, $this->connection->getConnection()->transaction(fn (): int => app(ScopeWidening::class)->widened($this->person, 'tenant-2')));
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

        self::assertTrue(app(LinkConfirmationGate::class)->allows($person, $this->connection));
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
     * admission, for this identity and connection, naming exactly the link.
     *
     * @return void
     */
    public function testIndependentAuthenticationConfirms(): void
    {
        $link = $this->linkByDomain();

        $link->forceFill(['state' => LinkState::SUSPENDED, 'suspended_at' => $this->clock->now()])->save();

        self::assertTrue($this->redeemLink()->isRedeemed());

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
     * Run a `link` flow for the person, through to its redemption.
     *
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeemLink(): RedemptionResult
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted(), (string) $completion->reason?->value);

        return $this->admit($completion, $start, Purpose::LINK, $this->person);
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
