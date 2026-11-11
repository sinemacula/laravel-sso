<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\Stages\DomainReservation;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainStanding;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Handoffs\HandoffCode;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;
use SineMacula\Laravel\Sso\Handoffs\RecheckLock;
use SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\DomainLinkEligibility;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\IdentityLock;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkingDiscovery;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Linking\ReservationDiscovery;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Models\IdentityGuard;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Preset;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\RecordsLockOrder;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Links\DelegatingLinkStorage;
use Tests\Fixtures\Links\FixedLinker;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Adversarial tests of linking by a verified domain (SSO-8.8, SSO-3.3), whose
 * failure is an account takeover. Everything goes through public completion and
 * redemption with one condition withdrawn at a time, at every boundary: the
 * domain's standing, its check age, its generation and grace; the membership's
 * acceptance against the verification; the matcher's input and answers; the
 * identity's scope and what it holds; the issuer's classification and
 * organisation; a SAML source's acknowledgement; the linking version;
 * reservations live, expired and replaced; identical deadlines; adapter issuers
 * and linkers; a contract's outage, which is never a refusal; a stored row
 * tampered with; and that nothing leaks.
 *
 * Without a reservation the result goes on unlinked, so a refused completion
 * ends in `unlinked`; a condition that fails at redemption is
 * `reservation_invalid`, and either way no link is left.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainLinkEligibility::class)]
#[CoversClass(ReservationDiscovery::class)]
#[CoversClass(IdentityLock::class)]
#[CoversClass(ReservationActivation::class)]
#[CoversClass(DomainReservation::class)]
#[CoversClass(LinkReservations::class)]
#[CoversClass(LinkStore::class)]
#[CoversClass(DomainStanding::class)]
final class DomainLinkEligibilityTest extends LinkingTestCase
{
    use CapturesLogs, RecordsLockOrder;

    /** @var string Google's issuer. */
    private const string GOOGLE = 'https://accounts.google.com';

    /** @var string The organisation's value. */
    private const string ORGANIZATION = 'acme.example';

    /** @var string The public reference of the flow a state is built for. */
    private const string STATE_REFERENCE = 'Rq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var int The linking maximum age by default, in seconds. */
    private const int MAX_AGE = 86400;

    /**
     * With every condition holding, the flow reserves and activates: what every
     * test below withdraws one condition from.
     *
     * @return void
     */
    public function testWithEveryConditionHoldingItLinks(): void
    {
        [$start, $completion] = $this->reserved();

        $answer = $this->admit($completion, $start);

        self::assertTrue($answer->isRedeemed());
        self::assertSame($this->person->id, $answer->linkedIdentity?->id);
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
    }

    /**
     * Rows of `[seconds since the last check, whether it allows linking]`.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideCheckAges(): iterable
    {
        yield 'just checked' => [0, true];
        yield 'one under the maximum' => [self::MAX_AGE - 1, true];
        yield 'exactly the maximum' => [self::MAX_AGE, true];
        yield 'one over the maximum' => [self::MAX_AGE + 1, false];
        yield 'a future check' => [-1, false];
    }

    /**
     * At completion, a check within the maximum age reserves, and one older or
     * future-dated does not.
     *
     * @param  int  $age
     * @param  bool  $allowed
     * @return void
     */
    #[DataProvider('provideCheckAges')]
    public function testTheCheckAgeAtCompletion(int $age, bool $allowed): void
    {
        $this->domain->forceFill(['last_successful_check_at' => $this->clock->now()->subSeconds($age)])->save();

        $this->start();

        $completion = $this->complete();

        if ($allowed) {
            self::assertTrue($completion->isCompleted());
            self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

            return;
        }

        $this->assertNothingReserved($completion);
    }

    /**
     * At redemption the same boundary holds again, on the same identity.
     *
     * @param  int  $age
     * @param  bool  $allowed
     * @return void
     */
    #[DataProvider('provideCheckAges')]
    public function testTheCheckAgeAtRedemption(int $age, bool $allowed): void
    {
        [$start, $completion] = $this->reserved();

        $this->domain->forceFill(['last_successful_check_at' => $this->clock->now()->subSeconds($age)])->save();

        $this->assertRedemption($completion, $start, $allowed);
    }

    /**
     * A shorter configured maximum age is the boundary, at it and one over.
     *
     * @return void
     */
    public function testAConfiguredMaximumAgeIsTheBoundary(): void
    {
        config()->set('sso.domains.linking_max_age_seconds', 3600);

        $this->domain->forceFill(['last_successful_check_at' => $this->clock->now()->subSeconds(3601)])->save();
        $this->start();
        $this->assertNothingReserved($this->complete());

        $this->domain->forceFill(['last_successful_check_at' => $this->clock->now()->subSeconds(3600)])->save();
        $this->start();

        self::assertTrue($this->complete()->isCompleted());
    }

    /**
     * Rows of `[what changes on the claim]`: a standing that allows no linking.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideDomainStandings(): iterable
    {
        yield 'lapsed' => [['state' => DomainState::LAPSED, 'verified_domain' => null, 'verified_at' => null]];
        yield 'pending' => [['state' => DomainState::PENDING, 'verified_domain' => null, 'verified_at' => null]];
        yield 'suspended, no grace' => [['linking_suspended_at' => 'now']];
        yield 'past its grace' => [['lapses_at' => 'now']];
        yield 'never checked' => [['last_successful_check_at' => null]];
    }

    /**
     * A domain lapsed, suspended, pending or never checked allows no linking at
     * completion; each between the reservation and the redemption activates
     * nothing, even with no withdrawal having run.
     *
     * @param  array<string, mixed>  $change
     * @return void
     */
    #[DataProvider('provideDomainStandings')]
    public function testADomainThatAllowsNoLinkingReservesNothing(array $change): void
    {
        $this->domain->forceFill($this->standing($change))->save();
        $this->start();

        $this->assertNothingReserved($this->complete());
    }

    /**
     * Each standing, between the reservation and the redemption.
     *
     * @param  array<string, mixed>  $change
     * @return void
     */
    #[DataProvider('provideDomainStandings')]
    public function testADomainThatAllowsNoLinkingActivatesNothing(array $change): void
    {
        [$start, $completion] = $this->reserved();

        $this->domain->forceFill($this->standing($change))->save();

        $this->assertRedemption($completion, $start, false);
    }

    /**
     * A domain removed between the reservation and the redemption leaves the
     * code to `reservation_invalid`, with no link.
     *
     * @return void
     */
    public function testADomainDeletedActivatesNothing(): void
    {
        [$start, $completion] = $this->reserved();

        $this->domain->delete();

        $this->assertRedemption($completion, $start, false);
    }

    /**
     * Discovery's grace period authorises nothing here: the domain still marks
     * the email as belonging to the connection, and links nothing.
     *
     * @return void
     */
    public function testAGracePeriodAllowsDiscoveryButNoLinking(): void
    {
        $this->domain->forceFill(['linking_suspended_at' => $this->clock->now(), 'lapses_at' => $this->clock->now()->addDay()])->save();

        $verified = null;

        Event::listen(ResultUnlinked::class, static function (ResultUnlinked $event) use (&$verified): void {
            $verified = $event->result->emailDomainVerified;
        });

        $this->start();

        $completion = $this->complete();

        self::assertTrue(DomainStanding::routes($this->domain, $this->clock->now()));
        self::assertTrue($verified);
        $this->assertNothingReserved($completion);
    }

    /**
     * A re-verification between the reservation and the redemption has a new
     * generation: the old reservation never activates, however good the rest.
     *
     * @return void
     */
    public function testAReverificationBetweenTheReservationAndTheRedemptionActivatesNothing(): void
    {
        [$start, $completion] = $this->reserved();

        $this->domain->forceFill(['verification_generation' => 2, 'verified_at' => $this->clock->now()->subSecond()])->save();

        $this->assertRedemption($completion, $start, false);
    }

    /**
     * Rows of `[seconds from the verification to the acceptance, whether it
     * counts]`: strictly before.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideAcceptances(): iterable
    {
        yield 'one second before' => [-1, true];
        yield 'exactly at it' => [0, false];
        yield 'one second after' => [1, false];
    }

    /**
     * Membership must predate the current verification, at completion.
     *
     * @param  int  $offset
     * @param  bool  $counts
     * @return void
     */
    #[DataProvider('provideAcceptances')]
    public function testTheMembershipAtCompletion(int $offset, bool $counts): void
    {
        $verifiedAt = $this->clock->now()->subHour();

        $this->domain->forceFill(['verified_at' => $verifiedAt, 'verification_generation' => 2])->save();
        $this->membership->standing = MembershipStanding::accepted($verifiedAt->addSeconds($offset));

        $this->start();

        $completion = $this->complete();

        if ($counts) {
            self::assertSame(2, Link::query()->sole()->reservation_domain_generation);

            return;
        }

        $this->assertNothingReserved($completion);
    }

    /**
     * The same at redemption, against the verification as it now stands.
     *
     * @param  int  $offset
     * @param  bool  $counts
     * @return void
     *
     * @throws \LogicException
     */
    #[DataProvider('provideAcceptances')]
    public function testTheMembershipAtRedemption(int $offset, bool $counts): void
    {
        [$start, $completion] = $this->reserved();

        $this->membership->standing = MembershipStanding::accepted($this->domain->verified_at?->addSeconds($offset) ?? throw new \LogicException('It is verified.'));

        $this->assertRedemption($completion, $start, $counts);
    }

    /**
     * No membership refuses, at completion and at redemption.
     *
     * @return void
     */
    public function testNoMembershipRefuses(): void
    {
        [$start, $completion] = $this->reserved();

        $this->membership->standing = MembershipStanding::none();

        $this->assertRedemption($completion, $start, false);

        $this->start();

        $this->assertNothingReserved($this->complete());
    }

    /**
     * Rows of `[the email, the domain the matcher receives, its claim's name]`:
     * the package adds no folding, so the matcher receives the email exactly as
     * asserted and the domain as SSO-3.1 compares one.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideEmails(): iterable
    {
        yield 'a subaddress' => ['a+b@example.com', 'example.com'];
        yield 'dots' => ['first.last@example.com', 'example.com'];
        yield 'a Unicode local part' => ["jos\u{00E9}@example.com", 'example.com'];
        yield 'a decomposed Unicode local part' => ["jose\u{0301}@example.com", 'example.com'];
        yield 'an upper case local part' => ['PERSON@example.com', 'example.com'];
        yield 'an upper case domain' => ['person@EXAMPLE.COM', 'example.com'];
        yield 'a trailing dot' => ['person@example.com.', 'example.com'];
        yield 'an IDN' => ["person@b\u{00FC}cher.com", 'xn--bcher-kva.com'];
        yield 'an upper case IDN' => ["person@B\u{00DC}CHER.COM", 'xn--bcher-kva.com'];
    }

    /**
     * The matcher receives the original email and the canonical domain, at
     * completion and at redemption, with the tenant.
     *
     * @param  string  $email
     * @param  string  $canonical
     * @return void
     */
    #[DataProvider('provideEmails')]
    public function testTheMatcherReceivesTheOriginalEmailAndTheCanonicalDomain(string $email, string $canonical): void
    {
        if ($canonical !== 'example.com') {
            $this->verifiedClaim($canonical);
        }

        $this->verifying->claims = $this->claims($email);

        [$start, $completion] = $this->reserved();

        self::assertTrue($this->admit($completion, $start)->isRedeemed());
        self::assertCount(3, $this->matcher->queries, 'Asked by plain read before the locks, under them, and at redemption.');

        foreach ($this->matcher->queries as $query) {
            self::assertSame($email, $query->email());
            self::assertSame($canonical, $query->domain);
            self::assertSame('tenant-1', $query->tenantId);
        }
    }

    /**
     * Rows of `[the email]`: a domain that is not the claim's, compared exactly
     * once canonical. A confusable, a subdomain, a parent and padding are other
     * domains, and the matcher is never asked.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOtherDomains(): iterable
    {
        yield 'a confusable, Cyrillic' => ["person@ex\u{0430}mple.com"];
        yield 'a subdomain' => ['person@mail.example.com'];
        yield 'a parent' => ['person@com'];
        yield 'another domain' => ['person@example.org'];
        yield 'a space after it' => ['person@example.com '];
        yield 'a space before it' => ['person@ example.com'];
        yield 'a new line after it' => ["person@example.com\n"];
        yield 'not a host name' => ['person@exa_mple.com'];
    }

    /**
     * Another domain reserves nothing, and its email is matched against nobody.
     *
     * @param  string  $email
     * @return void
     */
    #[DataProvider('provideOtherDomains')]
    public function testAnotherDomainReservesNothing(string $email): void
    {
        $this->verifying->claims = $this->claims($email);

        $this->start();

        $this->assertNothingReserved($this->complete());
        self::assertSame([], $this->matcher->queries);
    }

    /**
     * A domain verified for another connection, and a pending claim of this
     * one, link nothing.
     *
     * @return void
     */
    public function testADomainOfAnotherConnectionOrAPendingClaimReservesNothing(): void
    {
        $other = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'tenant_id' => 'tenant-2', 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);

        $this->makeDomain($other, 'other.example.com', [
            'state'                    => DomainState::VERIFIED,
            'verified_domain'          => 'other.example.com',
            'verified_at'              => $this->clock->now()->subDay(),
            'last_successful_check_at' => $this->clock->now(),
        ]);
        $this->makeDomain($this->connection, 'pending.example.com');

        foreach (['person@other.example.com', 'person@pending.example.com'] as $email) {

            $this->verifying->claims = $this->claims($email);

            $this->start();

            $this->assertNothingReserved($this->complete());
        }
    }

    /**
     * No match and more than one match reserve nothing.
     *
     * @return void
     */
    public function testNoMatchOrManyMatchesReserveNothing(): void
    {
        foreach ([LinkEmailMatch::none(), LinkEmailMatch::ambiguous()] as $match) {

            $this->matcher->match = $match;

            $this->start();

            $this->assertNothingReserved($this->complete());
        }
    }

    /**
     * At redemption, no match, many matches and a different sole match each
     * refuse: a different match is never the new target, so nothing is linked
     * to anybody.
     *
     * @return void
     */
    public function testAChangedMatchAtRedemptionIsNeverTheNewTarget(): void
    {
        $others = [
            LinkEmailMatch::none(),
            LinkEmailMatch::ambiguous(),
            LinkEmailMatch::exactlyOne(new IdentityReference('App\Models\User', '8')),
            LinkEmailMatch::exactlyOne(new IdentityReference('App\Models\Admin', '7')),
        ];

        foreach ($others as $match) {

            $this->matcher->match = LinkEmailMatch::exactlyOne($this->person);

            [$start, $completion] = $this->reserved();

            $this->matcher->match = $match;

            $this->assertRedemption($completion, $start, false);
        }
    }

    /**
     * Rows of `[the verdict]`: every answer but `within_tenant` refuses.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict}>
     */
    public static function provideRefusingVerdicts(): iterable
    {
        yield 'outside the tenant' => [ScopeVerdict::OUTSIDE_TENANT];
        yield 'unknown' => [ScopeVerdict::UNKNOWN];
    }

    /**
     * An identity holding a principal outside the tenant, or whose principals
     * are unknown, reserves nothing, and is asked about for the exact tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict  $verdict
     * @return void
     */
    #[DataProvider('provideRefusingVerdicts')]
    public function testTheScopeAtCompletion(ScopeVerdict $verdict): void
    {
        $this->scope->verdict = $verdict;

        $this->start();

        $this->assertNothingReserved($this->complete());
        self::assertSame([[$this->person->type, $this->person->id, 'tenant-1']], $this->scope->asked);
    }

    /**
     * The same at redemption: the matched identity gaining an outside principal
     * activates nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict  $verdict
     * @return void
     */
    #[DataProvider('provideRefusingVerdicts')]
    public function testTheScopeAtRedemption(ScopeVerdict $verdict): void
    {
        [$start, $completion] = $this->reserved();

        $this->scope->verdict = $verdict;

        $this->assertRedemption($completion, $start, false);
    }

    /**
     * A principal added and removed between the checks answers `within_tenant`
     * at redemption, and is caught all the same by the principal mutation.
     *
     * @return void
     */
    public function testAPrincipalAddedAndRemovedBetweenChecksIsCaughtByTheWidening(): void
    {
        [$start, $completion] = $this->reserved();

        $this->connection->getConnection()->transaction(fn (): int => app(ScopeWidening::class)->widened([$this->person], 'tenant-2', Clients::browser()));

        self::assertSame(ScopeVerdict::WITHIN_TENANT, $this->scope->verdict);

        $this->assertRedemption($completion, $start, false);
    }

    /**
     * Rows of `[claim value the result holds, whether it counts]`: a shared
     * issuer's organisation, compared exactly.
     *
     * @return iterable<string, array{0: ?string, 1: bool}>
     */
    public static function provideOrganizations(): iterable
    {
        yield 'exactly the value' => [self::ORGANIZATION, true];
        yield 'no claim' => [null, false];
        yield 'a wrong value' => ['other.example', false];
        yield 'another case' => ['ACME.example', false];
        yield 'a space after it' => [self::ORGANIZATION . ' ', false];
        yield 'a prefix of it' => ['acme', false];
    }

    /**
     * A connection classified shared needs exactly its organisation's value.
     *
     * @param  ?string  $organization
     * @param  bool  $counts
     * @return void
     */
    #[DataProvider('provideOrganizations')]
    public function testASharedIssuersOrganization(?string $organization, bool $counts): void
    {
        $this->classifyShared('org');

        $this->verifying->claims = $this->claims(self::EMAIL, $organization);

        $this->start();

        $completion = $this->complete();

        if ($counts) {
            self::assertSame($organization, Link::query()->sole()->reservation_organization);

            return;
        }

        $this->assertNothingReserved($completion);
    }

    /**
     * The value only in the mapped attributes does not count: the organisation
     * is the protocol's evidence, never a mapped attribute or the email's
     * domain.
     *
     * @return void
     */
    public function testTheValueOnlyInMappedAttributesDoesNotCount(): void
    {
        $this->classifyShared('org');

        $this->verifying->claims = new VerifiedClaims(
            VerifyingDriver::ISSUER,
            VerifyingDriver::SUBJECT,
            null,
            ['mail' => self::EMAIL, 'org' => self::ORGANIZATION],
            new AuthenticationContext($this->clock->now()),
            new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN),
        );

        $this->start();

        $this->assertNothingReserved($this->complete());
    }

    /**
     * Rows of `[what changes on the connection]`: what a shared issuer's policy
     * refuses, unset or incomplete.
     *
     * @return iterable<string, array{0: array<string, ?string>}>
     */
    public static function provideIncompleteSharedPolicies(): iterable
    {
        yield 'no value' => [['linking_organization_value' => null]];
        yield 'no claim' => [['linking_organization_claim' => null]];
        yield 'unclassified' => [['linking_issuer_class' => null]];
        yield 'a class nobody knows' => [['linking_issuer_class' => 'something']];
    }

    /**
     * An incomplete or unset policy refuses, even with the value in the result.
     *
     * @param  array<string, ?string>  $change
     * @return void
     */
    #[DataProvider('provideIncompleteSharedPolicies')]
    public function testAnIncompleteSharedPolicyRefuses(array $change): void
    {
        $this->classifyShared('org');
        $this->connection->forceFill($change)->save();

        $this->verifying->claims = $this->claims(self::EMAIL, self::ORGANIZATION);

        $this->start();

        $this->assertNothingReserved($this->complete());
    }

    /**
     * An unclassified issuer never means single organisation.
     *
     * @return void
     */
    public function testAnUnclassifiedIssuerRefuses(): void
    {
        $this->connection->forceFill(['linking_issuer_class' => null])->save();

        $this->start();

        $this->assertNothingReserved($this->complete());
    }

    /**
     * An issuer classified as one organisation's with no acknowledgement of
     * that reserves nothing.
     *
     * @return void
     */
    public function testASingleOrganizationNeedsItsAcknowledgement(): void
    {
        $this->connection->forceFill(['linking_acknowledged_at' => null])->save();

        $this->start();

        $this->assertNothingReserved($this->complete());
    }

    /**
     * Linking off, on the connection or by the feature, refuses at completion;
     * and either turned off by then refuses at redemption.
     *
     * @return void
     */
    public function testLinkingOffRefuses(): void
    {
        [$start, $completion] = $this->reserved();

        config()->set('sso.features.domain_linking', false);

        $this->assertRedemption($completion, $start, false);

        $this->start();

        $this->assertNothingReserved($this->complete());

        config()->set('sso.features.domain_linking', true);

        [$start, $completion] = $this->reserved();

        $this->connection->forceFill(['linking_enabled' => false])->save();

        $this->assertRedemption($completion, $start, false);

        $this->start();

        $this->assertNothingReserved($this->complete());
    }

    /**
     * Rows of `[classification, claim, the email's organisation, whether it
     * counts]`: Google's issuer, whatever a connection says.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: ?string, 3: bool}>
     */
    public static function provideBuiltInIssuers(): iterable
    {
        yield 'shared under its claim' => ['shared', 'hd', self::ORGANIZATION, true];
        yield 'shared under its claim, no value in the result' => ['shared', 'hd', null, false];
        yield 'shared under another claim' => ['shared', 'org', self::ORGANIZATION, false];
        yield 'classified single organisation' => ['single_organization', 'hd', self::ORGANIZATION, false];
        yield 'classified single organisation, no claim' => ['single_organization', null, null, false];
        yield 'unclassified' => [null, 'hd', self::ORGANIZATION, false];
    }

    /**
     * A built-in shared issuer needs `shared`, exactly its claim, and exactly
     * the value, wherever the connection's row came from.
     *
     * @param  ?string  $class
     * @param  ?string  $claim
     * @param  ?string  $organization
     * @param  bool  $counts
     * @return void
     */
    #[DataProvider('provideBuiltInIssuers')]
    public function testABuiltInSharedIssuer(?string $class, ?string $claim, ?string $organization, bool $counts): void
    {
        $this->connection->forceFill(['linking_issuer_class' => $class, 'linking_organization_claim' => $claim, 'linking_organization_value' => self::ORGANIZATION])->save();

        $this->verifying->claims = self::issuedBy(self::GOOGLE, $organization);

        $this->start();

        $completion = $this->complete();

        if ($counts) {
            self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

            return;
        }

        $this->assertNothingReserved($completion);
    }

    /**
     * Configuration attempting to downgrade a built-in issuer changes nothing.
     *
     * @return void
     */
    public function testConfigurationCannotDowngradeABuiltIn(): void
    {
        config()->set('sso.linking.shared_issuers', [self::GOOGLE => 'org']);

        $this->connection->forceFill(['linking_issuer_class' => 'shared', 'linking_organization_claim' => 'org', 'linking_organization_value' => self::ORGANIZATION])->save();

        $this->verifying->claims = self::issuedBy(self::GOOGLE, self::ORGANIZATION);

        $this->start();

        $this->assertNothingReserved($this->complete());
    }

    /**
     * An issuer configuration adds, and one a preset names, are enforced as a
     * built-in is.
     *
     * @return void
     */
    public function testAnIssuerConfigurationAddsOrAPresetNamesIsEnforced(): void
    {
        config()->set('sso.linking.shared_issuers', [VerifyingDriver::ISSUER => 'org']);

        $this->start();

        $this->assertNothingReserved($this->complete());

        config()->set('sso.linking.shared_issuers', []);

        app(ProtocolManager::class)->registerPreset(new Preset('verifying_shared', VerifyingDriver::NAME, ['issuer' => VerifyingDriver::ISSUER], [], 'org'));

        $this->start();

        $this->assertNothingReserved($this->complete());

        $this->classifyShared('org');

        $this->verifying->claims = $this->claims(self::EMAIL, self::ORGANIZATION);

        $this->start();

        self::assertTrue($this->complete()->isCompleted());
    }

    /**
     * Rows of `[what changes on the connection]`: a SAML source's requirements.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function provideSamlPolicies(): iterable
    {
        $complete = [
            'linking_saml_attribute'        => 'mail',
            'linking_saml_attribute_format' => 'a-format',
            'linking_acknowledged_at'       => CarbonImmutable::parse('2026-11-01T00:00:00Z'),
        ];

        yield 'complete' => [$complete, true];
        yield 'no acknowledgement' => [['linking_acknowledged_at' => null] + $complete, false];
        yield 'no attribute' => [['linking_saml_attribute' => null] + $complete, false];
        yield 'no format' => [['linking_saml_attribute_format' => null] + $complete, false];
    }

    /**
     * A linking email from a SAML attribute needs the attribute named and the
     * administrator's acknowledgement.
     *
     * @param  array<string, mixed>  $policy
     * @param  bool  $counts
     * @return void
     */
    #[DataProvider('provideSamlPolicies')]
    public function testASamlSourcesPolicy(array $policy, bool $counts): void
    {
        $this->connection->forceFill($policy)->save();

        $this->verifying->claims = new VerifiedClaims(
            VerifyingDriver::ISSUER,
            VerifyingDriver::SUBJECT,
            null,
            ['mail' => self::EMAIL],
            new AuthenticationContext($this->clock->now()),
            new LinkingEmail(self::EMAIL, LinkingEmailSource::SAML_ATTRIBUTE),
        );

        $this->start();

        $completion = $this->complete();

        if ($counts) {
            self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

            return;
        }

        $this->assertNothingReserved($completion);
    }

    /**
     * A linking version changed after validation reserves nothing; a changed
     * version on a reservation activates nothing.
     *
     * @return void
     */
    public function testALinkingVersionChangedReservesAndActivatesNothing(): void
    {
        $this->start();

        $this->verifying->onComplete = function (): void {
            $this->connection->forceFill(['linking_version' => 1])->save();
        };

        $this->assertNothingReserved($this->complete());

        [$start, $completion] = $this->reserved();

        self::assertSame(1, Link::query()->sole()->reservation_linking_version);

        $this->connection->forceFill(['linking_version' => 2])->save();

        $this->assertRedemption($completion, $start, false);
    }

    /**
     * Rows of `[the state of a row the identity holds in the connection,
     * whether it holds anything]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Links\Enums\LinkState, 1: ?int, 2: bool}>
     */
    public static function provideHeldRows(): iterable
    {
        yield 'active' => [LinkState::ACTIVE, null, true];
        yield 'suspended' => [LinkState::SUSPENDED, null, true];
        yield 'reserved, live' => [LinkState::RESERVED, 1, true];
        yield 'reserved, expiring now' => [LinkState::RESERVED, 0, false];
        yield 'reserved, expired' => [LinkState::RESERVED, -1, false];
    }

    /**
     * An identity already holding a link or a live reservation of another
     * subject reserves nothing, whatever the link limit allows; an expired one
     * holds nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @param  ?int  $expiresIn
     * @param  bool  $held
     * @return void
     */
    #[DataProvider('provideHeldRows')]
    public function testWhatTheIdentityHoldsAtCompletion(LinkState $state, ?int $expiresIn, bool $held): void
    {
        $this->app?->instance(LinkLimit::class, new readonly class implements LinkLimit {
            /**
             * Two links.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return int
             */
            #[\Override]
            public function maxLinks(IdentityReference $identity, SsoConnection $connection): int
            {
                unset($identity, $connection);

                return 2;
            }
        });

        $this->heldRow($state, $expiresIn);

        $this->start();

        $completion = $this->complete();

        if ($held) {
            self::assertSame(FailureReason::UNLINKED, $completion->reason);
            self::assertSame(1, Link::query()->count());

            return;
        }

        self::assertTrue($completion->isCompleted());
        self::assertSame(2, Link::query()->count());
    }

    /**
     * At redemption the reservation itself is left out of what the identity
     * holds, and a link or a live reservation gained since is not.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @param  ?int  $expiresIn
     * @param  bool  $held
     * @return void
     */
    #[DataProvider('provideHeldRows')]
    public function testWhatTheIdentityHoldsAtRedemption(LinkState $state, ?int $expiresIn, bool $held): void
    {
        [$start, $completion] = $this->reserved();

        $this->heldRow($state, $expiresIn);

        $answer = $this->admit($completion, $start);

        self::assertSame($held ? FailureReason::RESERVATION_INVALID : null, $answer->reason);
        self::assertSame($held ? 1 : 2, Link::query()->count());
    }

    /**
     * Another identity's row in the connection, and the identity's row in
     * another connection, hold nothing here.
     *
     * @return void
     */
    public function testAnotherIdentityOrConnectionHoldsNothing(): void
    {
        $this->heldRow(LinkState::ACTIVE, null, 'someone-else');

        $other = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);

        $this->heldRow(LinkState::ACTIVE, null, $this->person->id, $other->id);

        [$start, $completion] = $this->reserved(3);

        self::assertTrue($this->admit($completion, $start)->isRedeemed());
    }

    /**
     * A live reservation for this subject is `link_reserved`, and a second
     * completion offers nothing.
     *
     * @return void
     */
    public function testALiveReservationForThisSubjectIsLinkReserved(): void
    {
        $this->reserved();

        $offered = 0;

        Event::listen(ResultUnlinked::class, static function () use (&$offered): void {
            $offered++;
        });

        $this->start();

        self::assertSame(FailureReason::LINK_RESERVED, $this->complete()->reason);
        self::assertSame(0, $offered);
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
    }

    /**
     * An expired reservation is replaced under a new identity, and the old
     * handoff never activates the new row, even made to live longer than it: it
     * names the old identity.
     *
     * @return void
     */
    public function testAnExpiredReservationIsReplacedAndTheOldHandoffNeverActivatesTheNewRow(): void
    {
        [$oldStart, $old] = $this->reserved();

        $reservation = Link::query()->sole()->reservation_id;
        $code        = StoredCode::query()->sole();

        $code->forceFill(['expires_at' => $this->clock->now()->addHour()])->save();

        $this->clock->advance(60);

        $this->domain->forceFill(['last_successful_check_at' => $this->clock->now()])->save();

        $this->start();

        self::assertTrue($this->complete()->isCompleted());

        $row = Link::query()->sole();

        self::assertNotSame($reservation, $row->reservation_id);
        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($old, $oldStart)->reason);

        $kept = Link::query()->sole();

        self::assertSame(LinkState::RESERVED, $kept->state);
        self::assertSame($row->reservation_id, $kept->reservation_id);
    }

    /**
     * Rows of `[seconds the request has left, the handoff lifetime, the
     * expiry]`: the minimum of the request's expiry and the lifetime from now,
     * at each boundary.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int}>
     */
    public static function provideDeadlines(): iterable
    {
        yield 'the request first' => [30, 60, 30];
        yield 'one under the lifetime' => [59, 60, 59];
        yield 'exactly the lifetime' => [60, 60, 60];
        yield 'one over the lifetime' => [61, 60, 60];
        yield 'the lifetime first' => [600, 60, 60];
        yield 'a shorter lifetime' => [600, 10, 10];
        yield 'one second left' => [1, 60, 1];
    }

    /**
     * Reservation and handoff expire identically: the code as stored, the row
     * and the answer.
     *
     * @param  int  $left
     * @param  int  $lifetime
     * @param  int  $expiry
     * @return void
     */
    #[DataProvider('provideDeadlines')]
    public function testReservationAndHandoffExpireIdentically(int $left, int $lifetime, int $expiry): void
    {
        [, $completion, $expected] = $this->reservedWithin($left, $lifetime, $expiry);

        self::assertSame($expected, $completion->handoff?->expiresAt->toIso8601ZuluString());
        self::assertSame($expected, Link::query()->sole()->reservation_expires_at?->toIso8601ZuluString());
        self::assertSame($expected, StoredCode::query()->sole()->expires_at->toIso8601ZuluString());
    }

    /**
     * A second before that expiry it activates; at it, the code has expired,
     * the reservation goes with it and no link is left.
     *
     * @param  int  $left
     * @param  int  $lifetime
     * @param  int  $expiry
     * @return void
     */
    #[DataProvider('provideDeadlines')]
    public function testTheExpiryAtRedemption(int $left, int $lifetime, int $expiry): void
    {
        [$start, $completion] = $this->reservedWithin($left, $lifetime, $expiry);

        $this->clock->advance($expiry);

        self::assertSame(FailureReason::HANDOFF_EXPIRED, $this->admit($completion, $start)->reason);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A second before the expiry, it activates.
     *
     * @param  int  $left
     * @param  int  $lifetime
     * @param  int  $expiry
     * @return void
     */
    #[DataProvider('provideDeadlines')]
    public function testOneSecondBeforeTheExpiryItActivates(int $left, int $lifetime, int $expiry): void
    {
        [$start, $completion] = $this->reservedWithin($left, $lifetime, $expiry);

        $this->clock->advance($expiry - 1);

        self::assertTrue($this->admit($completion, $start)->isRedeemed());
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
    }

    /**
     * A row found expired under a handoff still live is refused too.
     *
     * @return void
     */
    public function testAReservationExpiredUnderALiveHandoffActivatesNothing(): void
    {
        [$start, $completion] = $this->reserved();

        Link::query()->sole()->forceFill(['reservation_expires_at' => $this->clock->now()])->save();

        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason);
    }

    /**
     * An adapter issuer answering no reference rolls the completion back: it
     * cannot hold a reservation, and nothing it did not bind is left.
     *
     * @return void
     */
    public function testAnIssuerWithNoReferenceRollsBack(): void
    {
        $this->app?->instance(HandoffIssuer::class, new RecordingHandoffIssuer);

        $this->assertIssuerRollsBack();
    }

    /**
     * An adapter issuer answering a later expiry rolls the completion back.
     *
     * @return void
     */
    public function testAnIssuerWithALaterExpiryRollsBack(): void
    {
        $this->app?->instance(HandoffIssuer::class, self::issuer(1));

        $this->assertIssuerRollsBack();
    }

    /**
     * An adapter issuer answering an earlier expiry binds the reservation to it
     * and its reference, so the two still expire together.
     *
     * @return void
     */
    public function testAnIssuerWithAnEarlierExpiryIsTheReservations(): void
    {
        $this->app?->instance(HandoffIssuer::class, self::issuer(-10));

        $this->start();

        self::assertTrue($this->complete()->isCompleted());

        $row = Link::query()->sole();

        self::assertSame('an-opaque-reference', $row->reservation_handoff);
        self::assertSame($this->clock->now()->addSeconds(50)->toIso8601ZuluString(), $row->reservation_expires_at?->toIso8601ZuluString());
    }

    /**
     * A linker not backed by link storage cannot hold a reservation: a
     * completion through it is a `LogicException` naming the problem, with
     * nothing written, and swapped in by redemption it activates nothing and
     * spends nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkerNotBackedByStorageFailsClosedBeforeWriting(): void
    {
        [$start, $completion] = $this->reserved();

        $row     = Link::query()->sole();
        $message = sprintf('[%s] bound as [%s] does not implement [%s]', FixedLinker::class, Linker::class, LinkStorage::class);

        $this->app?->instance(Linker::class, new FixedLinker(null));

        try {
            $this->connection->getConnection()->transaction(fn (): RedemptionResult => $this->admit($completion, $start));
            self::fail('A reservation activated through a linker that would ignore it.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString($message, $exception->getMessage());
        }

        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
        self::assertSame($row->id, Link::query()->sole()->id);
        self::assertNull(StoredCode::query()->sole()->redeemed_at);

        $this->start();

        try {
            $this->complete();
            self::fail('A completion wrote through a linker that would ignore it.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString($message, $exception->getMessage());
            self::assertStringStartsWith('Linking by a verified domain needs links its resolver reads', $exception->getMessage());
        }

        self::assertSame(1, Link::query()->count());
    }

    /**
     * A reservation locks in the package's order, its identity's guard first;
     * an activation too, with its claim before its code.
     *
     * @return void
     */
    public function testAReservationAndAnActivationLockInTheOrder(): void
    {
        $start = $this->start();

        $this->recordLockOrder();

        $completion = $this->complete();
        $order      = $this->lockOrder();
        $prepared   = array_slice($order, (int) array_search('identity guard', $order, true), 5);

        self::assertSame(['identity guard', 'connections ' . $this->connection->id, StorageConnection::table('domains.table'), 'request', 'link'], $prepared);

        $from = count($order);

        self::assertTrue($this->admit($completion, $start)->isRedeemed());
        self::assertSame(
            ['identity guard', 'connections ' . $this->connection->id . ', tenant-1', StorageConnection::table('domains.table'), 'code', 'link', 'link', 'link'],
            array_slice($this->lockOrder(), $from),
        );
    }

    /**
     * An identity matched under the locks whose guard was not taken is never
     * reserved for: the email moved to another person in between, or matched
     * nobody when it was first read. The completion refuses, its contracts of
     * that identity unasked, and nothing is written.
     *
     * @return void
     */
    public function testATargetWhoseGuardWasNotTakenIsRefused(): void
    {
        foreach ([LinkEmailMatch::exactlyOne(new IdentityReference('App\Models\User', '8')), LinkEmailMatch::none()] as $first) {

            $this->matcher->queued = [$first];
            $this->scope->asked    = [];

            $this->start();

            self::assertSame(FailureReason::RESERVATION_INVALID, $this->complete()->reason);
            self::assertSame(0, Link::query()->count());
            self::assertSame([], $this->scope->asked);
        }
    }

    /**
     * A subject held when it was first read and absent under the lock is a link
     * that changed, never an unlinked result: no provisioning is offered, and
     * nothing is written. Its claim was not locked, and no guard was taken.
     *
     * @return void
     */
    public function testASubjectHeldWhenReadAndAbsentUnderTheLockIsALinkThatChanged(): void
    {
        $this->makeLink($this->connection, VerifyingDriver::SUBJECT, [
            'issuer'        => VerifyingDriver::ISSUER,
            'identity_type' => $this->person->type,
            'identity_id'   => $this->person->id,
        ]);

        $this->app?->instance(Linker::class, new DelegatingLinkStorage(app(LinkStore::class), LinkResolution::absent()));

        $offered = 0;

        Event::listen(ResultUnlinked::class, static function () use (&$offered): void {
            $offered++;
        });

        $this->start();

        self::assertSame(FailureReason::LINK_CHANGED, $this->complete()->reason);
        self::assertSame(0, $offered);
        self::assertSame(0, IdentityGuard::query()->count());
    }

    /**
     * Discovery reads an expired reservation as absent, so it reserves anew
     * under the guard; a live one holds the subject, and takes no guard.
     *
     * @return void
     */
    public function testDiscoveryReadsAnExpiredReservationAsAbsent(): void
    {
        $this->makeLink($this->connection, VerifyingDriver::SUBJECT, [
            'issuer'                 => VerifyingDriver::ISSUER,
            'identity_type'          => $this->person->type,
            'identity_id'            => $this->person->id,
            'state'                  => LinkState::RESERVED,
            'provenance'             => LinkOrigin::VERIFIED_DOMAIN,
            'reservation_id'         => '01jbz000000000000000000001',
            'reservation_expires_at' => $this->clock->now()->addSecond(),
        ]);

        $this->start();

        self::assertSame(FailureReason::LINK_RESERVED, $this->complete()->reason);
        self::assertSame(0, IdentityGuard::query()->count());

        $this->clock->advance(1);

        $this->start();

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(1, IdentityGuard::query()->count());
    }

    /**
     * With the feature off, or the connection's linking off, nothing about a
     * completion touches linking: no guard, no claim locked, no contract asked.
     *
     * @return void
     */
    public function testNothingIsDiscoveredWithLinkingOff(): void
    {
        $asked = count($this->matcher->queries);

        config()->set('sso.features.domain_linking', false);

        $this->start();

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);

        config()->set('sso.features.domain_linking', true);

        $this->connection->forceFill(['linking_enabled' => false])->save();

        $this->start();

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertSame(0, IdentityGuard::query()->count());
        self::assertCount($asked, $this->matcher->queries);
    }

    /**
     * A wrapper that delegates to the store is the store: it reserves and
     * activates exactly as the store does, its own `resolve()` asked.
     *
     * @return void
     */
    public function testAWrapperThatDelegatesReservesAndActivates(): void
    {
        $wrapper = new DelegatingLinkStorage(app(LinkStore::class));

        $this->app?->instance(Linker::class, $wrapper);

        [$start, $completion] = $this->reserved();

        self::assertTrue($this->admit($completion, $start)->isRedeemed());
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, Link::query()->sole()->provenance);
        self::assertSame(1, $wrapper->resolutions, 'Resolved at completion; a reserved code is judged by its reservation.');
    }

    /**
     * A suspended link is not an unlinked subject: it is neither provisioned
     * nor reserved over, and stays suspended when the principal goes.
     *
     * @return void
     */
    public function testASuspendedLinkIsNeverProvisionedOrReserved(): void
    {
        [$start, $completion] = $this->reserved();

        self::assertTrue($this->admit($completion, $start)->isRedeemed());

        $offered = 0;

        Event::listen(ResultUnlinked::class, static function () use (&$offered): void {
            $offered++;
        });

        foreach ([ScopeVerdict::OUTSIDE_TENANT, ScopeVerdict::WITHIN_TENANT] as $verdict) {

            $this->scope->verdict = $verdict;

            $this->start();

            self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);
            self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
        }

        self::assertSame(0, $offered);
        self::assertNull(Link::query()->sole()->reservation_id);
    }

    /**
     * A subject linked to another identity is linked, whatever the email
     * matches: the link wins, and nothing is reserved.
     *
     * @return void
     */
    public function testALinkedSubjectIsNeverRelinked(): void
    {
        $subject = new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT);

        app(LinkStore::class)->create($this->connection, $subject, new IdentityReference('App\Models\User', 'owner'), LinkOrigin::PROVISIONING, Clients::browser());

        $start  = $this->start();
        $answer = $this->admit($this->complete(), $start);

        self::assertSame('owner', $answer->linkedIdentity?->id);
        self::assertSame([], $this->matcher->queries);
    }

    /**
     * Rows of `[the fixture that fails]`: each of the contracts that decide a
     * reservation, in the order they are asked.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideContracts(): iterable
    {
        yield 'the link email contract' => ['matcher'];
        yield 'the principal scope contract' => ['scope'];
        yield 'the tenant membership contract' => ['membership'];
    }

    /**
     * A contract's outage at completion is a server error, never `unlinked` and
     * never provisioning: the very exception propagates, T2 rolls back with no
     * reservation and no code, and the request stays consumed and unfinished,
     * with nothing offered.
     *
     * @param  string  $contract
     * @return void
     */
    #[DataProvider('provideContracts')]
    public function testAContractsOutageAtCompletionPropagates(string $contract): void
    {
        $offered = 0;

        Event::listen(ResultUnlinked::class, static function () use (&$offered): void {
            $offered++;
        });

        $failure = $this->failing($contract);

        $this->start();

        $this->assertPropagates($failure, fn (): CompletionResult => $this->complete());

        $request = AuthorizationRequest::query()->sole();

        self::assertSame(0, Link::query()->count());
        self::assertSame(0, StoredCode::query()->count());
        self::assertNotNull($request->consumed_at);
        self::assertNull($request->completed_at);
        self::assertSame(0, $offered);
        $this->assertNoFailure();
    }

    /**
     * A contract's outage at redemption rolls everything back rather than
     * refuse: the very exception propagates, the code is unspent, the
     * reservation stands exactly as it was, no failure is reported, and the
     * redemption retried activates it.
     *
     * @param  string  $contract
     * @return void
     */
    #[DataProvider('provideContracts')]
    public function testAContractsOutageAtRedemptionRollsItBack(string $contract): void
    {
        [$start, $completion] = $this->reserved();

        $row     = Link::query()->sole();
        $failure = $this->failing($contract);

        $this->assertPropagates($failure, fn (): mixed => $this->admit($completion, $start));

        $kept = Link::query()->sole();

        self::assertNull(StoredCode::query()->sole()->redeemed_at);
        self::assertSame(LinkState::RESERVED, $kept->state);
        self::assertSame($row->reservation_id, $kept->reservation_id);
        self::assertSame($row->reservation_handoff, $kept->reservation_handoff);
        $this->assertNoFailure();

        $this->matcher->failure    = null;
        $this->scope->failure      = null;
        $this->membership->failure = null;

        self::assertTrue($this->admit($completion, $start)->isRedeemed());
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
    }

    /**
     * An outage of the principal scope contract never latches a suspension on
     * an active domain link, at completion or at redemption: the link stays
     * active, with no `LinkSuspended`, and resolves once the contract is back.
     *
     * @return void
     */
    public function testAScopeOutageNeverSuspendsADomainLink(): void
    {
        [$start, $completion] = $this->reserved();

        self::assertTrue($this->admit($completion, $start)->isRedeemed());

        $version = $this->linksVersion();

        $start      = $this->start();
        $completion = $this->complete();

        $failure = $this->failing('scope');

        $this->assertPropagates($failure, fn (): mixed => $this->admit($completion, $start));

        $this->start();

        $this->assertPropagates($failure, fn (): CompletionResult => $this->complete());

        $kept = Link::query()->sole();

        self::assertSame(LinkState::ACTIVE, $kept->state);
        self::assertNull($kept->suspended_at);
        self::assertSame($version, $this->linksVersion());
        self::assertSame([], array_values(array_filter($this->recordedEvents(), static fn (object $event): bool => $event instanceof LinkSuspended)));

        $this->scope->failure = null;

        self::assertTrue($this->admit($completion, $start)->isRedeemed());
    }

    /**
     * A `link` asks neither the email nor the membership contract: only a
     * reservation stands on them, so an outage of either touches nothing else.
     *
     * @return void
     */
    public function testALinkAsksNoneOfTheReservationsContracts(): void
    {
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);

        $this->failing('matcher');
        $this->failing('membership');

        $start = $this->start(Purpose::LINK, $this->person);

        self::assertTrue($this->admit($this->complete(), $start, Purpose::LINK, $this->person)->isRedeemed());
    }

    /**
     * Rows of `[the column overwritten, the value]`: what binds a reservation
     * to its handoff, its flow and its subject.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideBindings(): iterable
    {
        yield 'the request reference' => ['reservation_reference', 'Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456'];
        yield 'the organisation' => ['reservation_organization', 'another-organization'];
        yield 'the email digest' => ['reservation_email_digest', str_repeat('a', 64)];
        yield 'the subject' => ['subject', 'another-subject'];
        yield 'the issuer' => ['issuer', 'https://another-issuer.example.com'];
        yield 'the NameID format' => ['name_id_format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'];
    }

    /**
     * A row that no longer holds exactly what it was reserved with activates
     * nothing, and the refusal removes it, by its own identity and handoff.
     *
     * @param  string  $column
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideBindings')]
    public function testATamperedBindingActivatesNothing(string $column, string $value): void
    {
        [$start, $completion] = $this->reserved();

        Link::query()->update([$column => $value]);

        $answer = $this->admit($completion, $start);

        self::assertSame(FailureReason::RESERVATION_INVALID, $answer->reason);
        self::assertNull($answer->linkedIdentity);
        self::assertNull($answer->linkId);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A row bound to another handoff is another handoff's: the redemption
     * refuses, activates nothing, and leaves the row and the links version
     * alone.
     *
     * @return void
     */
    public function testAReservationBoundToAnotherHandoffIsLeftAlone(): void
    {
        [$start, $completion] = $this->reserved();

        Link::query()->update(['reservation_handoff' => 'another-handoff']);

        $version = $this->linksVersion();
        $answer  = $this->admit($completion, $start);

        self::assertSame(FailureReason::RESERVATION_INVALID, $answer->reason);
        self::assertNull($answer->linkedIdentity);

        $kept = Link::query()->sole();

        self::assertSame(LinkState::RESERVED, $kept->state);
        self::assertSame('another-handoff', $kept->reservation_handoff);
        self::assertSame($version, $this->linksVersion());
    }

    /**
     * Rows of `[whether the connection, the handoff and the subject compared
     * are the row's, the seconds its reservation has left]`, each one thing
     * apart.
     *
     * @return iterable<string, array{0: bool, 1: bool, 2: bool, 3: int}>
     */
    public static function provideBoundParts(): iterable
    {
        yield 'every part' => [true, true, true, 1];
        yield 'another connection' => [false, true, true, 1];
        yield 'another handoff' => [true, false, true, 1];
        yield 'another subject' => [true, true, false, 1];
        yield 'expiring now' => [true, true, true, 0];
        yield 'expired' => [true, true, true, -1];
    }

    /**
     * A locked row is the handoff's reservation only when every part of it is,
     * and it expires after now.
     *
     * @param  bool  $connection
     * @param  bool  $handoff
     * @param  bool  $subject
     * @param  int  $expiresIn
     * @return void
     */
    #[DataProvider('provideBoundParts')]
    public function testIsBoundToJudgesEveryPart(bool $connection, bool $handoff, bool $subject, int $expiresIn): void
    {
        $this->reserved();

        Link::query()->update(['reservation_expires_at' => $this->clock->now()->addSeconds($expiresIn)->format('Y-m-d H:i:s.u')]);

        $row   = Link::query()->sole();
        $bound = app(LinkReservations::class)->isBoundTo(
            $row,
            $handoff ? (string) $row->reservation_handoff : 'another-handoff',
            $connection ? $this->connection->id : 'another-connection',
            new LinkSubject(VerifyingDriver::ISSUER, $subject ? VerifyingDriver::SUBJECT : 'another-subject'),
        );

        self::assertSame($connection && $handoff && $subject && $expiresIn > 0, $bound);
    }

    /**
     * The judgement holds the claim locked to the claim the row is bound to, by
     * its id as well as its generation: a row bound to another claim of the
     * connection, at the same generation, is refused though the locked claim
     * would allow it.
     *
     * @return void
     */
    public function testTheClaimLockedMustBeTheOneBound(): void
    {
        [, $completion] = $this->reserved();

        $code   = StoredCode::query()->sole();
        $row    = Link::query()->sole();
        $result = $this->resultOf($row->reservation_reference);

        self::assertNotNull($completion->handoff);

        $this->verifiedClaim('another.example.com');

        $binding = new HandoffBinding(reservationId: $row->reservation_id, handoffReference: $code->id);

        self::assertSame(RecheckOutcome::PASSED, $this->judged($result, $binding));

        Link::query()->update(['reservation_domain_id' => $this->otherClaimId()]);

        self::assertSame(RecheckOutcome::RESERVATION_INVALID, $this->judged($result, $binding));
    }

    /**
     * A row moved to another connection is refused by the judgement, though the
     * identity holds as many links here as eligibility asks.
     *
     * @return void
     */
    public function testARowInAnotherConnectionIsNotBound(): void
    {
        $this->reserved();

        $code   = StoredCode::query()->sole();
        $row    = Link::query()->sole();
        $result = $this->resultOf($row->reservation_reference);
        $other  = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);

        $binding = new HandoffBinding(reservationId: $row->reservation_id, handoffReference: $code->id);

        self::assertSame(RecheckOutcome::PASSED, $this->judged($result, $binding));

        Link::query()->update(['connection_id' => $other->id]);

        $this->makeLink($this->connection, 'held-here', ['identity_type' => $this->person->type, 'identity_id' => $this->person->id, 'state' => LinkState::ACTIVE]);

        self::assertSame(RecheckOutcome::RESERVATION_INVALID, $this->judged($result, $binding));
    }

    /**
     * A refused code's reservation is removed only by exactly its identity and
     * its handoff reference: a binding naming no reference, or another, removes
     * nothing and raises nothing, and the one naming it removes the row and
     * raises the links version by one. A reservation already gone raises
     * nothing either.
     *
     * @return void
     */
    public function testARefusedReservationIsDeletedOnlyByItsReference(): void
    {
        $this->reserved();

        $row          = Link::query()->sole();
        $reservations = app(LinkReservations::class);
        $version      = $this->linksVersion();

        $reservations->deleteRefused($this->connection->id, (string) $row->reservation_id, null);
        $reservations->deleteRefused($this->connection->id, (string) $row->reservation_id, 'another-handoff');

        self::assertSame(1, Link::query()->count());
        self::assertSame($version, $this->linksVersion());

        $reservations->deleteRefused($this->connection->id, (string) $row->reservation_id, (string) $row->reservation_handoff);

        self::assertSame(0, Link::query()->count());
        self::assertSame($version + 1, $this->linksVersion());

        $reservations->deleteRefused($this->connection->id, (string) $row->reservation_id, (string) $row->reservation_handoff);

        self::assertSame($version + 1, $this->linksVersion());
    }

    /**
     * No email, subject or organisation reaches an event, a log or a dump, on
     * the way through, whether it activates or refuses.
     *
     * @return void
     */
    public function testNothingLeaks(): void
    {
        $this->captureLogs();
        $this->classifyShared('org');

        $this->verifying->claims = $this->claims(self::EMAIL, self::ORGANIZATION);

        [$start, $completion] = $this->reserved();

        self::assertTrue($this->admit($completion, $start)->isRedeemed());

        Link::query()->delete();

        [$start, $completion] = $this->reserved();

        $this->scope->verdict = ScopeVerdict::UNKNOWN;

        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason);

        // The logger trims what it writes, so the subject is searched for as it
        // would appear there, which also finds it padded
        $needles = [self::EMAIL, self::ORGANIZATION, trim(VerifyingDriver::SUBJECT)];

        foreach ($this->recordedEvents() as $event) {
            foreach ($needles as $needle) {
                self::assertStringNotContainsString($needle, print_r($event, true), $event::class);
                self::assertStringNotContainsString($needle, (string) json_encode($event), $event::class);
                self::assertStringNotContainsString($needle, serialize($event), $event::class);
            }
        }

        $this->assertNothingLoggedContains(...$needles);
    }

    /**
     * A stored reservation shows neither its digest nor its organisation when
     * serialised, and keeps no email.
     *
     * @return void
     */
    public function testAStoredReservationKeepsNoEmail(): void
    {
        $this->classifyShared('org');

        $this->verifying->claims = $this->claims(self::EMAIL, self::ORGANIZATION);

        $this->reserved();

        $row     = Link::query()->sole();
        $encoded = (string) json_encode($row);

        self::assertStringNotContainsString(self::ORGANIZATION, $encoded);
        self::assertStringNotContainsString((string) $row->reservation_email_digest, $encoded);
        self::assertStringNotContainsString(self::EMAIL, print_r((array) $row->getConnection()->table($row->getTable())->where('id', $row->id)->first(), true));
    }

    /**
     * Everything holding, a state answers the identity and the terms it is to
     * be reserved on, exactly.
     *
     * @return void
     */
    public function testAnEligibleStateAnswersItsIdentityAndTerms(): void
    {
        $answer = self::eligibility()->atCompletion($this->eligibleState());

        self::assertNotNull($answer);
        self::assertSame($this->person, $answer['identity']);
        self::assertSame($this->connection, $answer['connection']);
        self::assertSame(VerifyingDriver::SUBJECT, $answer['result']->subject);
        self::assertSame(self::STATE_REFERENCE, $answer['terms']->reference->value);
        self::assertSame($this->connection->linking_version, $answer['terms']->linkingVersion);
        self::assertSame('2026-11-01T09:31:00+00:00', $answer['terms']->expiresAt->toIso8601String());
    }

    /**
     * A state with no result, or a result with no linking email, is answered
     * `null` before any contract is asked.
     *
     * @return void
     */
    public function testAStateWithNoLinkingEmailIsNoCandidate(): void
    {
        self::assertNull(self::eligibility()->atCompletion(self::arrivedState($this->connection->id)));
        self::assertNull(self::eligibility()->atCompletion($this->eligibleState()->withResult($this->resultWith(null))));
        self::assertSame([], $this->matcher->queries);
    }

    /**
     * A result of another purpose, or a state whose link is not known absent,
     * is answered `null` before any contract is asked.
     *
     * @return void
     */
    public function testOnlyASignInWhoseLinkIsAbsentIsACandidate(): void
    {
        $email     = new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN);
        $unknown   = self::consumedAs($this->connection, $this->domain)->withResult($this->resultWith($email));
        $otherwise = [
            'link'       => $this->eligibleState()->withResult($this->resultWith($email, Purpose::LINK)),
            'unresolved' => $unknown,
            'reserved'   => $unknown->withResolution(LinkResolution::reserved()),
        ];

        foreach ($otherwise as $name => $state) {
            self::assertNull(self::eligibility()->atCompletion($state), $name);
        }

        self::assertSame([], $this->matcher->queries);
    }

    /**
     * A candidate whose connection was never read is a misconfiguration.
     *
     * @return void
     */
    public function testACandidateWithNoConnectionIsALogicException(): void
    {
        $state = self::arrivedState($this->connection->id)
            ->withResult($this->resultWith(new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN)))
            ->withResolution(LinkResolution::absent());

        $this->expectExceptionObject(new \LogicException('A link is reserved once the connection is locked.'));

        self::eligibility()->atCompletion($state);
    }

    /**
     * Rows of `[which part of the consumed request is missing]`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMissingParts(): iterable
    {
        yield 'the request' => ['request'];
        yield 'what the driver was given of it' => ['consumed'];
        yield 'the application' => ['application'];
    }

    /**
     * A candidate holding only part of its consumed request is a
     * misconfiguration.
     *
     * @param  string  $missing
     * @return void
     */
    #[DataProvider('provideMissingParts')]
    public function testACandidateWithNoConsumedRequestIsALogicException(string $missing): void
    {
        $state = $this->eligibleState();
        $state = $state->withAuthorizationRequest(
            $missing === 'request' ? null : $state->authorizationRequest,
            $missing === 'consumed' ? null : $state->consumed,
            $missing === 'application' ? null : $state->application,
        );

        $this->expectExceptionObject(new \LogicException('A link is reserved once the request is consumed.'));

        self::eligibility()->atCompletion($state);
    }

    /**
     * A claim the state does not hold, one of another connection however named,
     * or one of another domain, allows nothing, whatever else holds.
     *
     * @return void
     */
    public function testTheClaimMustBeTheConnectionsOwnOfTheEmailsDomain(): void
    {
        $elsewhere = $this->domain->replicate()->forceFill(['connection_id' => '01jbanotherconnection00000']);
        $renamed   = $this->domain->replicate()->forceFill(['domain' => 'another.example.com']);

        self::assertNotNull(self::eligibility()->atCompletion($this->eligibleState()));
        self::assertNull(self::eligibility()->atCompletion($this->eligibleState()->withConnection($this->connection)));
        self::assertNull(self::eligibility()->atCompletion($this->eligibleState()->withConnection($this->connection, $elsewhere)));
        self::assertNull(self::eligibility()->atCompletion($this->eligibleState()->withConnection($this->connection, $renamed)));
    }

    /**
     * Another linker, or a linking version other than the one the evidence was
     * accepted under, allows nothing, each with everything else holding.
     *
     * @return void
     */
    public function testTheStoreAndTheLinkingVersionMustStand(): void
    {
        $stale = $this->eligibleState();

        $later = $this->clock->now()->addMinute();

        self::assertNull(self::eligibility()->atCompletion($stale->withValidation($this->connection->linking_version + 1, $later)));

        $this->app?->instance(Linker::class, new FixedLinker(null));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Linking by a verified domain needs links its resolver reads');

        self::eligibility()->atCompletion($stale);
    }

    /**
     * Rows of `[what changes on the connection, whether the feature stays on,
     * how the email is sourced]`: a policy withdrawn with the claim standing.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool, 2: \SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource}>
     */
    public static function provideWithdrawnPolicies(): iterable
    {
        $shared = ['linking_issuer_class' => 'shared', 'linking_organization_claim' => 'org', 'linking_organization_value' => self::ORGANIZATION];

        yield 'the feature off' => [[], false, LinkingEmailSource::ID_TOKEN];
        yield 'linking off' => [['linking_enabled' => false], true, LinkingEmailSource::ID_TOKEN];
        yield 'a SAML source unacknowledged' => [$shared + ['linking_acknowledged_at' => null], true, LinkingEmailSource::SAML_ATTRIBUTE];
        yield 'no classification, with an acknowledgement' => [['linking_issuer_class' => null], true, LinkingEmailSource::ID_TOKEN];
        yield 'one organisation unacknowledged' => [['linking_acknowledged_at' => null], true, LinkingEmailSource::ID_TOKEN];
    }

    /**
     * A policy that no longer allows the email allows nothing, the claim and
     * everything else standing.
     *
     * @param  array<string, mixed>  $change
     * @param  bool  $feature
     * @param  \SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource  $source
     * @return void
     */
    #[DataProvider('provideWithdrawnPolicies')]
    public function testAWithdrawnPolicyAllowsNothing(array $change, bool $feature, LinkingEmailSource $source): void
    {
        $this->connection->forceFill(['linking_saml_attribute' => 'mail', 'linking_saml_attribute_format' => 'urn:example:format', ...$change])->save();

        config()->set('sso.features.domain_linking', $feature);

        $state = $this->eligibleState()->withResult($this->resultWith(new LinkingEmail(self::EMAIL, $source, self::ORGANIZATION)));

        self::assertNull(self::eligibility()->atCompletion($state));
    }

    /**
     * The whitespace that would be trimmed from what an administrator typed is
     * no part of an address: the email matches nothing, and no contract is
     * asked.
     *
     * @return void
     */
    public function testAnEmailDomainWithWhitespaceMatchesNothing(): void
    {
        $state = $this->eligibleState()->withResult($this->resultWith(new LinkingEmail('person@example.com ', LinkingEmailSource::ID_TOKEN)));

        self::assertNull(self::eligibility()->atCompletion($state));
        self::assertSame([], $this->matcher->queries);
    }

    /**
     * What the identity may not be at completion, one condition at a time, with
     * the policy and the claim standing.
     *
     * @return void
     */
    public function testTheIdentityMustBeOneThatMayBeReserved(): void
    {
        $this->matcher->match = LinkEmailMatch::none();

        self::assertNull(self::eligibility()->atCompletion($this->eligibleState()), 'no match');

        $this->matcher->match = LinkEmailMatch::exactlyOne($this->person);
        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        self::assertNull(self::eligibility()->atCompletion($this->eligibleState()), 'a principal outside the tenant');

        $this->scope->verdict = ScopeVerdict::WITHIN_TENANT;

        self::assertNotNull(self::eligibility()->atCompletion($this->eligibleState()));

        $this->makeLink($this->connection, 'another-subject', ['issuer' => VerifyingDriver::ISSUER, 'identity_type' => $this->person->type, 'identity_id' => $this->person->id]);

        self::assertNull(self::eligibility()->atCompletion($this->eligibleState()), 'a link it already holds');
    }

    /**
     * At redemption, a claim not held, or a result with no linking email, is
     * refused before any contract is asked; everything holding, it stands.
     *
     * @return void
     */
    public function testWhatARedemptionHoldsDecidesBeforeAnyContract(): void
    {
        $this->makeLink($this->connection, VerifyingDriver::SUBJECT, [
            'issuer'        => VerifyingDriver::ISSUER,
            'identity_type' => $this->person->type,
            'identity_id'   => $this->person->id,
        ]);

        $result = $this->resultWith(new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN));

        self::assertFalse(self::eligibility()->isStillEligible($result, $this->person, $this->connection, null));
        self::assertFalse(self::eligibility()->isStillEligible($this->resultWith(null), $this->person, $this->connection, $this->domain));
        self::assertSame([], $this->matcher->queries);
        self::assertTrue(self::eligibility()->isStillEligible($result, $this->person, $this->connection, $this->domain));
    }

    /**
     * A reservation's identity is lower case, its row carries it, and what is
     * answered of its expiry is what the row stores: to the second.
     *
     * @return void
     */
    public function testAReservationAnswersWhatItsRowStores(): void
    {
        $this->clock = new FixedClock('2026-11-01T09:30:00.500Z');

        $this->app?->instance(Clock::class, $this->clock);

        $answer = self::eligibility()->atCompletion($this->eligibleState());

        self::assertNotNull($answer);

        $candidate = app(LinkReservations::class)->reserve($answer['connection'], LinkSubject::of($answer['result']), $answer['identity'], $answer['terms']);
        $row       = Link::query()->sole();

        self::assertNotNull($candidate);
        self::assertSame($row->reservation_id, $candidate->reservationId);
        self::assertSame(strtolower($candidate->reservationId), $candidate->reservationId);
        self::assertSame('2026-11-01T09:31:00.000000Z', $candidate->expiresAt->toISOString());
    }

    /**
     * A reservation, its activation, a refused redemption's deletion and an
     * expired reservation's replacement each raise the links version by one.
     *
     * @return void
     */
    public function testEachChangeOfAReservationRaisesTheLinksVersion(): void
    {
        $base = $this->linksVersion();

        [$start, $completion] = $this->reserved();

        self::assertSame($base + 1, $this->linksVersion());
        self::assertTrue($this->admit($completion, $start)->isRedeemed());
        self::assertSame($base + 2, $this->linksVersion());
    }

    /**
     * Rows of `[seconds to the reservation's expiry, or `null` for none,
     * whether the row is replaced]`.
     *
     * @return iterable<string, array{0: ?int, 1: bool}>
     */
    public static function provideReplaceableReservations(): iterable
    {
        yield 'none stated' => [null, true];
        yield 'at its expiry' => [0, true];
        yield 'a second left' => [1, false];
    }

    /**
     * Only a reservation no longer live is replaced, raising the links version
     * by one when it is.
     *
     * @param  ?int  $seconds
     * @param  bool  $replaced
     * @return void
     */
    #[DataProvider('provideReplaceableReservations')]
    public function testOnlyAnExpiredReservationIsReplaced(?int $seconds, bool $replaced): void
    {
        $subject = new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT);

        $this->makeLink($this->connection, VerifyingDriver::SUBJECT, [
            'issuer'                 => VerifyingDriver::ISSUER,
            'subject_key'            => $subject->key(),
            'identity_type'          => $this->person->type,
            'identity_id'            => $this->person->id,
            'state'                  => LinkState::RESERVED,
            'reservation_id'         => '01jbexamplereservation0001',
            'reservation_expires_at' => $seconds === null ? null : $this->clock->now()->addSeconds($seconds),
        ]);

        $base = $this->linksVersion();

        app(LinkReservations::class)->replaceExpired($this->connection, $subject);

        self::assertSame($replaced ? 0 : 1, Link::query()->count());
        self::assertSame($replaced ? $base + 1 : $base, $this->linksVersion());
    }

    /**
     * An identity holding as many links as it may is reserved nothing: at the
     * limit, not only over it.
     *
     * @return void
     */
    public function testAnIdentityAtItsLimitIsReservedNothing(): void
    {
        $answer = self::eligibility()->atCompletion($this->eligibleState());

        self::assertNotNull($answer);

        $this->makeLink($this->connection, 'another-subject', ['issuer' => VerifyingDriver::ISSUER, 'identity_type' => $this->person->type, 'identity_id' => $this->person->id]);

        self::assertNull(app(LinkReservations::class)->reserve($answer['connection'], LinkSubject::of($answer['result']), $answer['identity'], $answer['terms']));
        self::assertSame(1, Link::query()->count());
    }

    /**
     * Rows of `[the reservation the handoff names, its reference]`: a handoff
     * bound to less than both is bound to no reservation.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideUnboundHandoffs(): iterable
    {
        yield 'neither' => [null, null];
        yield 'no reservation' => [null, 'a-handoff'];
        yield 'no reference' => ['01jbexamplereservation0001', null];
    }

    /**
     * Such a handoff activates nothing.
     *
     * @param  ?string  $reservation
     * @param  ?string  $reference
     * @return void
     */
    #[DataProvider('provideUnboundHandoffs')]
    public function testAHandoffBoundToLessThanBothIsInvalid(?string $reservation, ?string $reference): void
    {
        $binding = new HandoffBinding(reservationId: $reservation, handoffReference: $reference);

        self::assertSame(RecheckOutcome::RESERVATION_INVALID, $this->judged($this->resultOf(self::STATE_REFERENCE), $binding));
    }

    /**
     * Activating a reservation that was never judged to be there is a
     * misconfiguration.
     *
     * @return void
     */
    public function testActivatingWhatIsNotThereIsALogicException(): void
    {
        $connection = Connection::query()->whereKey($this->connection->id)->sole();
        $lock       = RecheckLock::held('tenant-1', $connection->id, 'web', $connection, null, $this->domain);
        $context    = new RedemptionContext($this->resultOf(self::STATE_REFERENCE), new HandoffBinding, $lock, $connection, Clients::browser(), null);

        $this->expectExceptionObject(new \LogicException('A reservation is activated once it is judged.'));

        app(ReservationActivation::class)->activate($context);
    }

    /**
     * Rows of `[seconds left on the request, whether a reservation is made]`:
     * either side of its expiry.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideTimeLeft(): iterable
    {
        yield 'a second past' => [-1, false];
        yield 'at its expiry' => [0, false];
        yield 'a second left' => [1, true];
    }

    /**
     * A reservation needs a moment still to be redeemed in.
     *
     * @param  int  $left
     * @param  bool  $eligible
     * @return void
     */
    #[DataProvider('provideTimeLeft')]
    public function testAReservationNeedsTimeLeft(int $left, bool $eligible): void
    {
        self::assertSame($eligible, self::eligibility()->atCompletion($this->eligibleState($left)) !== null);
    }

    /**
     * Complete an eligible flow, holding its reservation; with others in the
     * table, the count given.
     *
     * @param  int  $rows
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: \SineMacula\Laravel\Sso\Completion\CompletionResult}
     */
    private function reserved(int $rows = 1): array
    {
        $start      = $this->start();
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted(), (string) $completion->reason?->value);
        self::assertSame($rows, Link::query()->count());
        self::assertSame(1, Link::query()->where('state', LinkState::RESERVED->value)->count());

        return [$start, $completion];
    }

    /**
     * Complete a flow with the time left on its request and the handoff
     * lifetime given, and answer it with its expected expiry.
     *
     * @param  int  $left
     * @param  int  $lifetime
     * @param  int  $expiry
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: \SineMacula\Laravel\Sso\Completion\CompletionResult, 2: string}
     */
    private function reservedWithin(int $left, int $lifetime, int $expiry): array
    {
        config()->set('sso.applications.web.handoff_ttl_seconds', $lifetime);

        $start = $this->start();

        AuthorizationRequest::query()->sole()->forceFill(['expires_at' => $this->clock->now()->addSeconds($left)])->save();

        $completion = $this->complete();

        self::assertTrue($completion->isCompleted(), (string) $completion->reason?->value);

        return [$start, $completion, $this->clock->now()->addSeconds($expiry)->toIso8601ZuluString()];
    }

    /**
     * Make the named scripted contract throw, and answer what it throws.
     *
     * @param  string  $contract
     * @return \RuntimeException
     *
     * @throws \LogicException
     */
    private function failing(string $contract): \RuntimeException
    {
        $failure = new \RuntimeException('The application\'s store is down.');

        match ($contract) {
            'matcher'    => $this->matcher->failure    = $failure,
            'scope'      => $this->scope->failure      = $failure,
            'membership' => $this->membership->failure = $failure,
            default      => throw new \LogicException(sprintf('No contract is named [%s].', $contract)),
        };

        return $failure;
    }

    /**
     * Assert the callback throws exactly the failure.
     *
     * @param  \RuntimeException  $failure
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private function assertPropagates(\RuntimeException $failure, \Closure $callback): void
    {
        try {
            $callback();
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);

            return;
        }

        self::fail('What should have propagated went on.');
    }

    /**
     * The eligibility judged.
     *
     * @return \SineMacula\Laravel\Sso\Linking\DomainLinkEligibility
     */
    private static function eligibility(): DomainLinkEligibility
    {
        return app(DomainLinkEligibility::class);
    }

    /**
     * A state that has only arrived.
     *
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private static function arrivedState(string $connectionId): CompletionState
    {
        return CompletionState::arrived($connectionId, new CompletionRequest('GET', '', []), Clients::browser());
    }

    /**
     * The state of a `sign_in` whose request was consumed, its connection and
     * claim locked, with a minute's handoff lifetime.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  int  $left
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private static function consumedAs(Connection $connection, Domain $domain, int $left = 600): CompletionState
    {
        $now     = CarbonImmutable::parse('2026-11-01T09:30:00Z');
        $request = (new AuthorizationRequest)->forceFill(['expires_at' => $now->addSeconds($left)]);

        return self::arrivedState($connection->id)
            ->withConnection($connection, $domain)
            ->withAuthorizationRequest(
                $request,
                new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString(self::STATE_REFERENCE), $now),
                Application::fromSettings('web', ['redirect_uri' => 'https://app.example.com/sso', 'handoff_ttl_seconds' => 60]),
            )
            ->withValidation($connection->linking_version, $now->addMinute());
    }

    /**
     * A state that everything allows, unless a test changes it.
     *
     * @param  int  $left
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private function eligibleState(int $left = 600): CompletionState
    {
        $this->connection->refresh();

        return self::consumedAs($this->connection, $this->domain, $left)
            ->withConnection($this->connection, $this->domain, LinkingDiscovery::open($this->person))
            ->withResult($this->resultWith(new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN)))
            ->withResolution(LinkResolution::absent());
    }

    /**
     * A result of the state's flow with the linking email and purpose given.
     *
     * @param  ?\SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function resultWith(?LinkingEmail $email, Purpose $purpose = Purpose::SIGN_IN): VerifiedResult
    {
        return new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $this->connection->id,
            tenantId: 'tenant-1',
            protocol: VerifyingDriver::NAME,
            application: 'web',
            purpose: $purpose,
            requestReference: RequestReference::fromString(self::STATE_REFERENCE),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext($this->clock->now()),
            linkingEmail: $email,
        );
    }

    /**
     * The connection's links version, read again.
     *
     * @return int
     */
    private function linksVersion(): int
    {
        return Connection::query()->whereKey($this->connection->id)->sole()->links_version;
    }

    /**
     * The id of the connection's claim other than the one the row is bound to.
     *
     * @return string
     */
    private function otherClaimId(): string
    {
        return $this->domain->newQuery()->where('domain', 'another.example.com')->sole()->id;
    }

    /**
     * What the driver verified, for the flow with the reference.
     *
     * @param  ?string  $reference
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function resultOf(?string $reference): VerifiedResult
    {
        return new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $this->connection->id,
            tenantId: 'tenant-1',
            protocol: VerifyingDriver::NAME,
            application: 'web',
            purpose: Purpose::SIGN_IN,
            requestReference: RequestReference::fromString((string) $reference),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext($this->clock->now()),
            linkingEmail: new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN),
        );
    }

    /**
     * What the activation judges of the row, in a transaction, with the real
     * claim locked and the connection as it is now.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $binding
     * @return \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     */
    private function judged(VerifiedResult $result, HandoffBinding $binding): RecheckOutcome
    {
        $connection = Connection::query()->whereKey($this->connection->id)->sole();
        $lock       = RecheckLock::held('tenant-1', $connection->id, 'web', $connection, null, $this->domain->refresh(), $this->person);

        return $connection->getConnection()->transaction(
            static fn (): RecheckOutcome => app(ReservationActivation::class)->judge(new RedemptionContext($result, $binding, $lock, $connection, Clients::browser(), null)),
        );
    }

    /**
     * Assert the completion reserved nothing and went on unlinked.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @return void
     */
    private function assertNothingReserved(CompletionResult $completion): void
    {
        self::assertSame(FailureReason::UNLINKED, $completion->reason);
        self::assertNull($completion->handoff);
        self::assertSame(0, Link::query()->where('state', LinkState::RESERVED->value)->count());
    }

    /**
     * Redeem the code and assert it activated exactly the reservation, or that
     * it was `reservation_invalid` with no link left.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  bool  $activates
     * @return void
     */
    private function assertRedemption(CompletionResult $completion, StartResult $start, bool $activates): void
    {
        $answer = $this->admit($completion, $start);

        if ($activates) {
            self::assertTrue($answer->isRedeemed());
            self::assertSame($this->person->id, $answer->linkedIdentity?->id);
            self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);

            return;
        }

        self::assertSame(FailureReason::RESERVATION_INVALID, $answer->reason);
        self::assertNull($answer->linkedIdentity);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Assert the completion throws the issuer's refusal and leaves nothing.
     *
     * @return void
     */
    private function assertIssuerRollsBack(): void
    {
        $this->start();

        try {
            $this->complete();
            self::fail('The completion went on.');
        } catch (\LogicException $exception) {
            self::assertSame('A handoff issuer must store a reservation\'s binding, and never a later expiry than it was given (SSO-8.8).', $exception->getMessage());
        }

        self::assertSame(0, Link::query()->count());
        self::assertNull(AuthorizationRequest::query()->sole()->completed_at);
    }

    /**
     * Classify the connection shared under the claim, with the expected value.
     *
     * @param  string  $claim
     * @return void
     */
    private function classifyShared(string $claim): void
    {
        $this->connection->forceFill(['linking_issuer_class' => 'shared', 'linking_organization_claim' => $claim, 'linking_organization_value' => self::ORGANIZATION])->save();
    }

    /**
     * Make a verified claim of this connection, checked now.
     *
     * @param  string  $domain
     * @return void
     */
    private function verifiedClaim(string $domain): void
    {
        $this->makeDomain($this->connection, $domain, [
            'state'                    => DomainState::VERIFIED,
            'verified_domain'          => $domain,
            'verified_at'              => $this->clock->now()->subDay(),
            'verification_generation'  => 1,
            'last_successful_check_at' => $this->clock->now(),
        ]);
    }

    /**
     * A row the person holds, of another subject, in the connection given, or
     * this one.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @param  ?int  $expiresIn
     * @param  ?string  $identityId
     * @param  ?string  $connectionId
     * @return void
     */
    private function heldRow(LinkState $state, ?int $expiresIn, ?string $identityId = null, ?string $connectionId = null): void
    {
        $key = new LinkSubject(VerifyingDriver::ISSUER, 'another-subject');

        (new Link)->forceFill([
            'connection_id'          => $connectionId ?? $this->connection->id,
            'issuer'                 => $key->issuer,
            'subject'                => $key->subject,
            'subject_key'            => $key->key(),
            'identity_type'          => $this->person->type,
            'identity_id'            => $identityId ?? $this->person->id,
            'state'                  => $state,
            'provenance'             => LinkOrigin::VERIFIED_DOMAIN,
            'reservation_id'         => $expiresIn === null ? null : strtolower((string) Str::ulid()),
            'reservation_expires_at' => $expiresIn === null ? null : $this->clock->now()->addSeconds($expiresIn),
        ])->save();
    }

    /**
     * What a standing's row means, now.
     *
     * @param  array<string, mixed>  $change
     * @return array<string, mixed>
     */
    private function standing(array $change): array
    {
        return array_map(fn (mixed $value): mixed => $value === 'now' ? $this->clock->now() : $value, $change);
    }

    /**
     * Claims from the issuer, with the organisation.
     *
     * @param  string  $issuer
     * @param  ?string  $organization
     * @return \SineMacula\Laravel\Sso\Results\VerifiedClaims
     */
    private static function issuedBy(string $issuer, ?string $organization): VerifiedClaims
    {
        return new VerifiedClaims(
            $issuer,
            VerifyingDriver::SUBJECT,
            null,
            ['mail' => self::EMAIL],
            new AuthenticationContext(CarbonImmutable::parse('2026-11-01T09:29:00Z')),
            new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN, $organization),
        );
    }

    /**
     * An adapter's issuer, answering an opaque reference and the grant's expiry
     * moved by the seconds given.
     *
     * @param  int  $seconds
     * @return \SineMacula\Laravel\Sso\Contracts\HandoffIssuer
     */
    private static function issuer(int $seconds): HandoffIssuer
    {
        return new readonly class ($seconds) implements HandoffIssuer {
            /**
             * Constructor.
             *
             * @param  int  $seconds
             */
            public function __construct(

                /** How far the expiry answered is from the grant's. */
                private int $seconds,
            ) {}

            /**
             * Answer a code with the expiry moved.
             *
             * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffGrant  $grant
             * @return \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff
             *
             * @throws \Random\RandomException
             */
            #[\Override]
            public function issue(HandoffGrant $grant): IssuedHandoff
            {
                return new IssuedHandoff(HandoffCode::generate(), $grant->expiresAt->addSeconds($this->seconds), 'an-opaque-reference');
            }
        };
    }
}
