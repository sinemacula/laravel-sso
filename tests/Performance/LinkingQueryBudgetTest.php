<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\Stages\DomainReservation;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\DomainLinkEligibility;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\IdentityGuard;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Linking\ScriptedEmailMatcher;
use Tests\Fixtures\Linking\ScriptedPrincipalScope;
use Tests\Fixtures\Linking\ScriptedTenantMembership;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Query budgets for linking by a verified domain (SSO-8.8, SSO-11.3, SSO-11.5),
 * each measured once the counters exist, so a completion first costs two
 * updates and a redemption one; the scripted contracts cost nothing:
 *
 * - a reservation is what a completion is (six reads, five writes), and: before
 *   the locks, the plain reads of the subject's row and the claim; in T2 the
 *   identity's guard, the claim's lock, the subject's row, what the identity
 *   holds, the subject's reserved row and what it holds again, the row and the
 *   links version, the code and the flows version, and the binding: thirteen
 *   reads, eleven writes;
 * - an ordinary linked sign-in through a connection with linking on takes no
 *   guard and no claim: the plain read of its row stands where the claim's lock
 *   stood, so it costs what it did; with the feature off, or linking off, it
 *   reads neither;
 * - an activation is what a redemption is (four reads, four writes), and: the
 *   reservation's identity and domain id, its guard, the claim's lock, the row
 *   twice and what the identity holds, the row, the links version and the
 *   guard's mark that the identity has held a domain link: nine reads, eight
 *   writes;
 * - a refusal at redemption: nine reads (what the identity holds, read before
 *   any contract is asked; the row again to delete it), and the guard, the
 *   counter, the single-use record, the code, the row and the links version;
 * - a domain's removal is what it is (four reads, two writes), and the links
 *   version when it deleted anything;
 * - each withdrawal is one delete, and the links version when it deleted
 *   anything;
 * - a settings change: the plain read and the lock, the save and the delete,
 *   and the links version when it deleted anything; a change of nothing writes
 *   nothing; a stale caller reads once;
 * - a resolution is one locking read, and for an active link of a `sign_in` the
 *   stamp, or for one found outside the tenant the connection's lock, the row
 *   read again locked, and the row and the links version; of unknown scope it
 *   is the read alone, and of another purpose too;
 * - a widening: the guard, the rows, the connections' lock, the rows locked,
 *   and the row and the links version; with none it is the guard and the two
 *   reads of the rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainReservation::class)]
#[CoversClass(DomainLinkEligibility::class)]
#[CoversClass(ReservationActivation::class)]
#[CoversClass(LinkReservations::class)]
#[CoversClass(ReservationWithdrawal::class)]
#[CoversClass(LinkStore::class)]
#[CoversClass(LinkingPolicyService::class)]
#[CoversClass(ScopeWidening::class)]
final class LinkingQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-budgeted-request-1';

    /** @var string The challenge of the verifier (RFC 7636, appendix B). */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var string The client's verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var string The linking email. */
    private const string EMAIL = 'person@example.com';

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection with linking on. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\Domain Its verified claim. */
    private Domain $domain;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity the email matches. */
    private IdentityReference $person;

    /** @var \Tests\Fixtures\Linking\ScriptedPrincipalScope The principal scope contract. */
    private ScriptedPrincipalScope $scope;

    /**
     * Bind the store and the contracts, register the driver and create the
     * connection, its claim and the counters.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now          = $this->clock->now();
        $this->person = new IdentityReference('App\Models\User', '7');
        $this->scope  = new ScriptedPrincipalScope;
        $driver       = new VerifyingDriver;

        $this->app?->instance('request', Request::create('/auth/sso', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(Linker::class, app(LinkStore::class));
        $this->app?->instance(LinkEmailMatcher::class, new ScriptedEmailMatcher(LinkEmailMatch::exactlyOne($this->person)));
        $this->app?->instance(PrincipalScope::class, $this->scope);
        $this->app?->instance(TenantMembership::class, new ScriptedTenantMembership(MembershipStanding::accepted($now->subDays(2))));

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.domain_linking', true);
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $driver->claims = new VerifiedClaims(
            VerifyingDriver::ISSUER,
            VerifyingDriver::SUBJECT,
            null,
            ['mail' => self::EMAIL],
            new AuthenticationContext($now),
            new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN),
        );

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->connection = $this->makeConnection([
            'protocol'                => VerifyingDriver::NAME,
            'enabled'                 => true,
            'settings'                => ['issuer' => VerifyingDriver::ISSUER],
            'attribute_mapping'       => ['email' => 'mail'],
            'linking_enabled'         => true,
            'linking_issuer_class'    => 'single_organization',
            'linking_acknowledged_at' => CarbonImmutable::parse('2026-11-01T00:00:00Z'),
        ]);

        $this->domain = $this->makeDomain($this->connection, 'example.com', [
            'state'                    => DomainState::VERIFIED,
            'verified_domain'          => 'example.com',
            'verified_at'              => $now->subDay(),
            'verification_generation'  => 1,
            'last_successful_check_at' => $now,
        ]);

        $this->completeAtCallback('a-state-that-creates-the-counters');
        app(HandoffRedemption::class)->redeem(Purpose::SIGN_IN, 'web', $this->connection->id, 'not-a-code', self::VERIFIER, Clients::browser());
    }

    /**
     * A reservation is thirteen reads and eleven writes.
     *
     * @return void
     */
    public function testAReservationIsThirteenReadsAndElevenWrites(): void
    {
        $this->request(self::STATE);

        $result = $this->assertQueryBudget(13, 11, fn (): CompletionResult => $this->completeAtCallback(self::STATE));

        self::assertTrue($result->isCompleted());
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
    }

    /**
     * An activation is nine reads and eight writes, the guard, its mark that
     * the identity has held a domain link and the first sign-in's mark among
     * them; the next through the connection is seven, the guard's mark sent
     * again and changing nothing.
     *
     * @return void
     */
    public function testAnActivationIsNineReadsAndEightWrites(): void
    {
        $first  = $this->reservedCode('a-first-state');
        $answer = $this->assertQueryBudget(9, 8, fn (): RedemptionResult => $this->admitted($first));

        self::assertTrue($answer->isRedeemed());
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);

        Link::query()->delete();

        $second = $this->reservedCode('a-second-state');

        self::assertTrue($this->assertQueryBudget(9, 7, fn (): RedemptionResult => $this->admitted($second))->isRedeemed());
    }

    /**
     * A refusal at redemption is nine reads and six writes: no link is made,
     * and the row is deleted.
     *
     * @return void
     */
    public function testARefusalAtRedemptionIsNineReadsAndSixWrites(): void
    {
        $code = $this->reservedCode(self::STATE);

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $this->assertQueryBudget(9, 6, fn (): RedemptionResult => $this->admitted($code));

        self::assertSame(0, Link::query()->count());
    }

    /**
     * A domain's removal is four reads and two writes, and the links version
     * when it deleted anything.
     *
     * @return void
     */
    public function testRemovingADomainWithAReservation(): void
    {
        $this->row(LinkState::RESERVED, 'a', 60, $this->domain->id);

        $this->assertQueryBudget(4, 3, fn () => app(DomainService::class)->remove('tenant-1', $this->connection->id, 'example.com', Clients::browser()));

        self::assertSame(0, Link::query()->count());
    }

    /**
     * Each withdrawal is one delete, and the links version when it deleted
     * anything.
     *
     * @return void
     */
    public function testEachWithdrawalIsADeleteAndTheVersion(): void
    {
        self::assertSame(0, $this->assertQueryBudget(0, 1, fn (): int => ReservationWithdrawal::ofConnection($this->connection)));
        self::assertSame(0, $this->assertQueryBudget(0, 1, fn (): int => ReservationWithdrawal::ofDomain($this->connection, $this->domain)));

        $this->row(LinkState::RESERVED, 'a', 60, $this->domain->id);

        self::assertSame(1, $this->assertQueryBudget(0, 2, fn (): int => ReservationWithdrawal::ofDomain($this->connection, $this->domain)));

        $this->row(LinkState::RESERVED, 'b', 60);
        $this->row(LinkState::RESERVED, 'c', 60);

        self::assertSame(2, $this->assertQueryBudget(0, 2, fn (): int => ReservationWithdrawal::ofConnection($this->connection)));

        $rows = [$this->row(LinkState::RESERVED, 'd', 60), $this->row(LinkState::ACTIVE, 'e')];

        self::assertSame(1, $this->assertQueryBudget(0, 2, fn (): int => ReservationWithdrawal::ofRows($this->connection, $rows)));
    }

    /**
     * A settings change is two reads and two writes, and the links version when
     * it deleted anything; a change of nothing writes nothing; a stale caller
     * reads once.
     *
     * @return void
     */
    public function testASettingsChange(): void
    {
        $change = fn (array $changes): ConnectionResult => app(LinkingPolicyService::class)->change('tenant-1', $this->connection->id, $changes, Clients::browser());

        $this->connection->forceFill(['linking_acknowledged_at' => null])->save();

        self::assertTrue($this->assertQueryBudget(2, 2, static fn (): ConnectionResult => $change(['acknowledged' => true]))->isChanged());

        $this->row(LinkState::RESERVED, 'a', 60);

        $shared = ['acknowledged' => false, 'issuer_class' => 'shared', 'organization_claim' => 'org', 'organization_value' => 'x'];

        self::assertTrue($this->assertQueryBudget(2, 3, static fn (): ConnectionResult => $change($shared))->isChanged());
        self::assertTrue($this->assertQueryBudget(2, 0, static fn (): ConnectionResult => $change([]))->isSucceeded());

        $this->app?->instance(Freshness::class, FakeFreshness::stale());

        self::assertTrue($this->assertQueryBudget(1, 0, static fn (): ConnectionResult => $change(['enabled' => false]))->isRefused());
    }

    /**
     * A resolution is one locking read, and for an active link by a verified
     * domain the stamp, or, found outside the tenant, two reads more (the
     * connection's lock and the row read again locked) and the row and the
     * links version; of unknown scope, suspended or reserved it is the read
     * alone.
     *
     * @return void
     */
    public function testAResolution(): void
    {
        $store = app(LinkStore::class);

        $this->row(LinkState::ACTIVE, VerifyingDriver::SUBJECT, null, null, $this->person->id);

        self::assertTrue($this->assertQueryBudget(1, 1, fn (): LinkResolution => $store->resolve($this->verifiedResult(), Clients::browser()))->isLinked());

        $this->scope->verdict = ScopeVerdict::UNKNOWN;

        self::assertTrue($this->assertQueryBudget(1, 0, fn (): LinkResolution => $store->resolve($this->verifiedResult(), Clients::browser()))->isScopeUnknown());

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        self::assertTrue($this->assertQueryBudget(3, 2, fn (): LinkResolution => $store->resolve($this->verifiedResult(), Clients::browser()))->isSuspended());
        self::assertTrue($this->assertQueryBudget(1, 0, fn (): LinkResolution => $store->resolve($this->verifiedResult(), Clients::browser()))->isSuspended());

        Link::query()->delete();

        self::assertTrue($this->assertQueryBudget(1, 0, fn (): LinkResolution => $store->resolve($this->verifiedResult(), Clients::browser()))->isAbsent());

        $this->row(LinkState::RESERVED, VerifyingDriver::SUBJECT, 60);

        self::assertTrue($this->assertQueryBudget(1, 0, fn (): LinkResolution => $store->resolve($this->verifiedResult(), Clients::browser()))->isReserved());
    }

    /**
     * A widening with nothing to do is its guard and two reads of the rows;
     * with a link, three reads, the connections' lock among them, and the
     * guard, the row and the links version.
     *
     * @return void
     */
    public function testAWidening(): void
    {
        $widen = fn (): int => $this->connection->getConnection()->transaction(fn (): int => app(ScopeWidening::class)->widened([$this->person], 'tenant-2', Clients::browser()));

        self::assertSame(0, $this->assertQueryBudget(2, 1, $widen));

        $this->row(LinkState::ACTIVE, 'a', null, null, $this->person->id);

        self::assertSame(1, $this->assertQueryBudget(3, 3, $widen));
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * An ordinary linked sign-in through a connection with linking on takes no
     * guard and locks no claim: the plain read of its row stands where the
     * claim's lock stood, so its cost is unchanged. With the feature off it
     * reads neither, one read fewer, and takes no guard.
     *
     * @return void
     */
    public function testAnOrdinaryLinkedSignInTakesNoGuard(): void
    {
        $this->row(LinkState::ACTIVE, VerifyingDriver::SUBJECT, null, null, $this->person->id);

        $this->scope->verdict = ScopeVerdict::WITHIN_TENANT;

        $this->request(self::STATE);

        self::assertTrue($this->assertQueryBudget(8, 8, fn (): CompletionResult => $this->completeAtCallback(self::STATE))->isCompleted());
        self::assertSame(0, IdentityGuard::query()->count());

        config()->set('sso.features.domain_linking', false);

        $this->request('a-second-state');

        self::assertTrue($this->assertQueryBudget(7, 8, fn (): CompletionResult => $this->completeAtCallback('a-second-state'))->isCompleted());
        self::assertSame(0, IdentityGuard::query()->count());
    }

    /**
     * Complete the state's request at the callback.
     *
     * @param  string  $state
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function completeAtCallback(string $state): CompletionResult
    {
        return app(CompletionService::class)->complete(
            CompletionEndpoint::CALLBACK,
            $this->connection->id,
            new CompletionRequest('GET', 'state=' . $state, []),
            Clients::browser(),
        );
    }

    /**
     * Store a request through the connection, started with the state.
     *
     * @param  string  $state
     * @return void
     */
    private function request(string $state): void
    {
        $this->makeAuthorizationRequest($this->connection, ['state_digest' => hash('sha256', $state), 'handoff_challenge' => self::CHALLENGE]);
    }

    /**
     * Reserve, and answer the code.
     *
     * @param  string  $state
     * @return string
     */
    private function reservedCode(string $state): string
    {
        $this->request($state);

        return (string) $this->completeAtCallback($state)->handoff?->code->reveal();
    }

    /**
     * Redeem the code in a transaction.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function admitted(string $code): RedemptionResult
    {
        $admit = fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $code, self::VERIFIER, Clients::browser());

        return $this->connection->getConnection()->transaction($admit);
    }

    /**
     * What the connection's result is, for a resolution.
     *
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function verifiedResult(): VerifiedResult
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
            requestReference: RequestReference::fromString('Gq8tVv3w0kLmNoPqRsTuVwXyZ0123456'),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext(CarbonImmutable::parse('2026-10-31T12:00:00Z')),
        );
    }

    /**
     * A row with verified domain provenance in the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @param  string  $subject
     * @param  ?int  $expiresIn
     * @param  ?string  $domainId
     * @param  ?string  $identityId
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function row(LinkState $state, string $subject, ?int $expiresIn = null, ?string $domainId = null, ?string $identityId = null): Link
    {
        $key  = new LinkSubject(VerifyingDriver::ISSUER, $subject);
        $link = new Link;

        $link->forceFill([
            'connection_id'          => $this->connection->id,
            'issuer'                 => $key->issuer,
            'subject'                => $key->subject,
            'subject_key'            => $key->key(),
            'identity_type'          => 'App\Models\User',
            'identity_id'            => $identityId ?? 'identity-' . $subject,
            'state'                  => $state,
            'provenance'             => LinkOrigin::VERIFIED_DOMAIN,
            'reservation_id'         => $expiresIn === null ? null : strtolower((string) Str::ulid()),
            'reservation_expires_at' => $expiresIn === null ? null : $this->clock->now()->addSeconds($expiresIn),
            'reservation_domain_id'  => $domainId,
        ])->save();

        return $link;
    }
}
