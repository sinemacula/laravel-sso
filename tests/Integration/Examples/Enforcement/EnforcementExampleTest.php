<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Enforcement;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Enforcement\Enums\EnforcementStatus;
use SineMacula\Laravel\Sso\Enforcement\ExemptionGate;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/enforcement.md` (SSO-4.1 to SSO-4.6, SSO-12.5),
 * on the shared example harness, with the application's own tenants and
 * sessions in its own tables and its contracts bound by its service provider:
 * an administrator turns a tenant's rule on, refused until a connection has
 * completed a sign-in, and the application's revocation ends, in the same
 * transaction, the sessions of the tenant and of the tenant that inherits its
 * rule that no satisfying connection established; turning it off revokes
 * nothing; the stored rule is read back; the tenant authentication policy
 * admits a compliant session, refuses a password session, and admits the
 * break-glass administrator's through the exemption gate, which reports it;
 * and disabling the connection or removing the link revokes the sessions
 * established through it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnforcementService::class)]
#[CoversClass(EnforcementPolicy::class)]
#[CoversClass(ExemptionGate::class)]
final class EnforcementExampleTest extends ExampleTestCase
{
    /** @var string The tenant that inherits the rule of the harness's tenant. */
    private const string CHILD = 'tenant-1-child';

    /** @var string A tenant with no rule and no connection. */
    private const string OTHER = 'tenant-2';

    /** @var string The identity type the application names its users by. */
    private const string USER_TYPE = 'App\Models\User';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's identity provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \Tests\Integration\Examples\Enforcement\Tenant The tenant whose rule changes. */
    private Tenant $tenant;

    /** @var \Tests\Integration\Examples\Enforcement\User The administrator who changes it. */
    private User $administrator;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person who signs in through the connection. */
    private IdentityReference $person;

    /** @var list<\SineMacula\Laravel\Sso\Events\EnforcementChanged> Each change reported. */
    private array $changes = [];

    /** @var list<\SineMacula\Laravel\Sso\Events\ExemptionUsed> Each exemption reported. */
    private array $exemptions = [];

    /**
     * Switch enforcement on, create the application's tables and tenant tree,
     * register its service provider, make the tenant's OIDC connection, link
     * the person to it, and listen for what is reported.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.features.enforcement', true);

        Schema::create(Tenant::TABLE, static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('enforcement_root_id')->nullable();
        });

        Schema::create(UserSession::TABLE, static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('user_type');
            $table->string('user_id');
            $table->string('tenant_id');
            $table->string('sso_connection_id')->nullable();
            $table->string('sso_link_id')->nullable();
            $table->string('enforcement_version')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->string('revoked_reason')->nullable();
        });

        $this->tenant = Tenant::query()->create(['id' => self::TENANT]);

        Tenant::query()->create(['id' => self::CHILD, 'enforcement_root_id' => self::TENANT]);
        Tenant::query()->create(['id' => self::OTHER]);

        app()->register(AppServiceProvider::class);

        $this->provider      = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId  = $this->makeOidcConnection($this->provider);
        $this->administrator = new User(['id' => 'admin-1']);
        $this->person        = new IdentityReference(self::USER_TYPE, 'person-1');

        $this->linkThroughFlow($this->provider, $this->connectionId, $this->person);

        Event::listen(EnforcementChanged::class, function (EnforcementChanged $event): void {
            $this->changes[] = $event;
        });

        Event::listen(ExemptionUsed::class, function (ExemptionUsed $event): void {
            $this->exemptions[] = $event;
        });
    }

    /**
     * Drop the application's tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(UserSession::TABLE);
        Schema::dropIfExists(Tenant::TABLE);

        parent::tearDown();
    }

    /**
     * Once the connection has completed a sign-in, turning the rule on stores
     * it with a new lower-case ULID, reports it with the administrator, and
     * revokes in the same change the password sessions of the tenant and of the
     * tenant that inherits its rule, leaving the session established through
     * the connection and another tenant's; the rule reads back as stored, and
     * giving it again, in any order, is `unchanged`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTurningEnforcementOnRevokesTheSessionsItNoLongerAllows(): void
    {
        $this->signIn('session-sso', self::TENANT);
        $this->recordSession('session-password', 'person-2', self::TENANT);
        $this->recordSession('session-child', 'person-3', self::CHILD);
        $this->recordSession('session-other', 'person-4', self::OTHER);

        $tenant       = $this->tenant;
        $connectionId = $this->connectionId;
        $user         = $this->administrator;

        // @snippet-start enforcement-service
        $enforcement = app(EnforcementService::class);
        // @snippet-end enforcement-service
        $client  = Clients::browser();
        $request = self::requestOnSession('/admin/sso/enforcement');
        // @snippet-start enforcement-update
        $result = $enforcement->update(
            $tenant->id,
            true,
            [$connectionId],
            $client,
            new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $request->session()->getId()),
        );

        self::assertSame(EnforcementStatus::UPDATED, $result->status);

        $version = $result->enforcement?->version; // a new lower-case ULID on every change
        // @snippet-end enforcement-update
        self::assertMatchesRegularExpression('/^[0-9a-hjkmnp-tv-z]{26}$/', (string) $version);

        self::assertSame([
            'session-child'    => RevocationReason::ENFORCEMENT_CHANGED->value,
            'session-other'    => null,
            'session-password' => RevocationReason::ENFORCEMENT_CHANGED->value,
            'session-sso'      => null,
        ], $this->revocations());

        self::assertCount(1, $this->changes);
        self::assertSame($version, $this->changes[0]->version);
        self::assertNull($this->changes[0]->previousVersion);
        self::assertSame(User::class, $this->changes[0]->context->actingIdentityMorphClass);
        self::assertSame('admin-1', $this->changes[0]->context->actingIdentityId);

        // @snippet-start enforcement-get
        $summary = $enforcement->get($tenant->id);

        self::assertTrue($summary->enabled);
        self::assertSame([$connectionId], $summary->connectionIds); // the ids stored, in id order
        self::assertSame($version, $summary->version); // null while the tenant never had a rule
        self::assertSame('2026-11-01T09:30:00Z', $summary->changedAt?->toIso8601ZuluString()); // CarbonImmutable in UTC, or null
        // @snippet-end enforcement-get
        $again = app(EnforcementService::class)->update(self::TENANT, true, [$connectionId, $connectionId], Clients::browser());

        self::assertSame(EnforcementStatus::UNCHANGED, $again->status);
        self::assertSame($version, $again->enforcement?->version);
        self::assertCount(1, $this->changes);
    }

    /**
     * Turning the rule off stores a new version, reports the change with the
     * version it replaced, and revokes nothing: the session that met the rule
     * stays, and so does a password session started once it was off.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTurningEnforcementOffRevokesNothing(): void
    {
        $this->signIn('session-sso', self::TENANT);

        $on = $this->turnOn();

        $this->recordSession('session-password', 'person-2', self::TENANT);

        $off = app(EnforcementService::class)->update(self::TENANT, false, [], Clients::browser());

        self::assertSame(EnforcementStatus::UPDATED, $off->status);
        self::assertNotSame($on, $off->enforcement?->version);
        self::assertSame(['session-password' => null, 'session-sso' => null], $this->revocations());
        self::assertCount(2, $this->changes);
        self::assertSame($on, $this->changes[1]->previousVersion);
        self::assertFalse(app(Enforcement::class)->policy(self::TENANT, self::APPLICATION)->isRequired());
    }

    /**
     * A change is refused, and writes, revokes and reports nothing, while the
     * feature is off, while no connection given has completed a sign-in, for a
     * connection the tenant does not have, and for a caller who did not
     * authenticate recently enough.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAChangeIsRefusedUntilItCanBeMade(): void
    {
        $this->recordSession('session-password', 'person-2', self::TENANT);

        config()->set('sso.features.enforcement', false);

        self::assertSame(FailureReason::FEATURE_DISABLED, app(EnforcementService::class)->update(self::TENANT, true, [$this->connectionId], Clients::browser())->reason);

        config()->set('sso.features.enforcement', true);

        $enforcement = app(EnforcementService::class);

        self::assertSame(FailureReason::COMPLETED_SIGN_IN_REQUIRED, $enforcement->update(self::TENANT, true, [$this->connectionId], Clients::browser())->reason);

        $unknown = $enforcement->update(self::TENANT, true, [$this->connectionId, 'another-tenants'], Clients::browser());

        self::assertSame(EnforcementStatus::INVALID, $unknown->status);
        self::assertSame('connection_ids.1', $unknown->violations[0]->setting);
        self::assertSame(ViolationCode::UNKNOWN, $unknown->violations[0]->code);

        $this->signIn('session-sso', self::TENANT);
        $this->freshness->staleFor(FreshnessOperation::ENFORCEMENT_UPDATE);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, app(EnforcementService::class)->update(self::TENANT, true, [$this->connectionId], Clients::browser())->reason);

        self::assertNull(app(EnforcementService::class)->get(self::TENANT)->version);
        self::assertSame(['session-password' => null, 'session-sso' => null], $this->revocations());
        self::assertSame([], $this->changes);
    }

    /**
     * A tenant that never had a rule reads as off, with no connection, no
     * version and no time, and its policy requires nothing.
     *
     * @return void
     */
    public function testATenantThatNeverHadARuleRequiresNothing(): void
    {
        $summary = app(EnforcementService::class)->get(self::OTHER);

        self::assertFalse($summary->enabled);
        self::assertSame([], $summary->connectionIds);
        self::assertNull($summary->version);
        self::assertNull($summary->changedAt);

        $policy = app(Enforcement::class)->policy(self::OTHER, self::APPLICATION);

        self::assertFalse($policy->isRequired());
        self::assertTrue($policy->isSatisfiedBy('any-connection'));
    }

    /**
     * Through the application's tenant tree, a tenant that inherits its root's
     * rule is answered with the root as the enforcing tenant, satisfied by the
     * root's connection alone, at the root's version; a root answers itself.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAChildTenantFollowsItsRootsRule(): void
    {
        $this->signIn('session-sso', self::TENANT);

        $version = $this->turnOn();
        $policy  = app(Enforcement::class)->policy(self::CHILD, self::APPLICATION);

        self::assertSame(self::CHILD, $policy->tenantId);
        self::assertSame(self::TENANT, $policy->enforcingTenantId);
        self::assertTrue($policy->isRequired());
        self::assertSame([$this->connectionId], $policy->connectionIds);
        self::assertSame($version, $policy->version);
        self::assertSame(self::OTHER, app(Enforcement::class)->policy(self::OTHER, self::APPLICATION)->enforcingTenantId);
    }

    /**
     * Under the rule, the policy admits a session established through the
     * satisfying connection, in the tenant and in the tenant that inherits its
     * rule, and a password session in a tenant with no rule, recording the
     * version each was judged against; it admits the break-glass
     * administrator's, reported once as `ExemptionUsed` with the session and
     * the version, and refuses a password session, with no exemption reported.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testThePolicyAdmitsOnlyCompliantOrExemptSessions(): void
    {
        $this->signIn('session-sso', self::TENANT);

        $version = $this->turnOn();
        $policy  = new TenantAuthenticationPolicy;

        self::assertTrue($policy->admits($this->recordSession('session-child', 'person-1', self::CHILD, $this->connectionId), Clients::browser()));
        self::assertTrue($policy->admits($this->recordSession('session-other', 'person-4', self::OTHER), Clients::browser()));
        self::assertTrue($policy->admits(UserSession::query()->findOrFail('session-sso'), Clients::browser()));
        self::assertSame($version, UserSession::query()->findOrFail('session-sso')->enforcement_version);
        self::assertNull(UserSession::query()->findOrFail('session-other')->enforcement_version);

        self::assertTrue($policy->admits($this->recordSession('session-break-glass', BreakGlassExemption::ADMINISTRATOR, self::CHILD), Clients::browser()));
        self::assertFalse($policy->admits($this->recordSession('session-password', 'person-2', self::TENANT), Clients::browser()));

        // The break-glass session's alone: the refused one reported nothing
        self::assertCount(1, $this->exemptions);
        self::assertSame('session-break-glass', $this->exemptions[0]->context->sessionId);
        self::assertSame(BreakGlassExemption::ADMINISTRATOR, $this->exemptions[0]->context->identityId);
        self::assertSame(self::CHILD, $this->exemptions[0]->context->tenantId);
        self::assertSame($version, $this->exemptions[0]->enforcementVersion);
    }

    /**
     * Disabling the connection revokes every session established through it,
     * whichever tenant it is active in now, and no other.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testDisablingAConnectionRevokesItsSessions(): void
    {
        $this->signIn('session-sso', self::TENANT);
        $this->recordSession('session-child', 'person-1', self::CHILD, $this->connectionId);
        $this->recordSession('session-password', 'person-2', self::TENANT);

        self::assertTrue(app(ConnectionLifecycle::class)->disable(self::TENANT, $this->connectionId, Clients::browser())->isSucceeded());

        self::assertSame([
            'session-child'    => RevocationReason::CONNECTION_DISABLED->value,
            'session-password' => null,
            'session-sso'      => RevocationReason::CONNECTION_DISABLED->value,
        ], $this->revocations());
    }

    /**
     * Removing the link revokes the sessions established through it, and no
     * other.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRemovingALinkRevokesItsSessions(): void
    {
        $session = $this->signIn('session-sso', self::TENANT);

        $this->recordSession('session-password', 'person-1', self::TENANT);

        self::assertTrue(app(LinkService::class)->remove($this->person, (string) $session->sso_link_id, Clients::browser())->isRemoved());

        self::assertSame([
            'session-password' => null,
            'session-sso'      => RevocationReason::LINK_REMOVED->value,
        ], $this->revocations());
    }

    /**
     * Sign the person in through the connection, and record the session the
     * application establishes, active in the tenant given.
     *
     * @param  string  $sessionId
     * @param  string  $tenantId
     * @return \Tests\Integration\Examples\Enforcement\UserSession
     *
     * @throws \Random\RandomException
     */
    private function signIn(string $sessionId, string $tenantId): UserSession
    {
        $signedIn = $this->signInThroughFlow($this->provider, $this->connectionId, $sessionId);

        self::assertTrue($signedIn->isAdmitted());

        return $this->recordSession($sessionId, $this->person->id, $tenantId, $this->connectionId, $signedIn->linkId);
    }

    /**
     * Record a session of the user, active in the tenant, established through
     * the connection and the link given, or without SSO when none is.
     *
     * @param  string  $sessionId
     * @param  string  $userId
     * @param  string  $tenantId
     * @param  ?string  $connectionId
     * @param  ?string  $linkId
     * @return \Tests\Integration\Examples\Enforcement\UserSession
     */
    private function recordSession(string $sessionId, string $userId, string $tenantId, ?string $connectionId = null, ?string $linkId = null): UserSession
    {
        return UserSession::query()->create([
            'id'                => $sessionId,
            'user_type'         => self::USER_TYPE,
            'user_id'           => $userId,
            'tenant_id'         => $tenantId,
            'sso_connection_id' => $connectionId,
            'sso_link_id'       => $linkId,
        ]);
    }

    /**
     * Turn the tenant's rule on, satisfied by the connection, and answer its
     * version.
     *
     * @return string
     */
    private function turnOn(): string
    {
        $result = app(EnforcementService::class)->update(self::TENANT, true, [$this->connectionId], Clients::browser());

        self::assertSame(EnforcementStatus::UPDATED, $result->status);

        return (string) $result->enforcement?->version;
    }

    /**
     * Why each of the application's sessions was revoked, by its id, or `null`
     * for one still active.
     *
     * @return array<array-key, mixed>
     */
    private function revocations(): array
    {
        return UserSession::query()->orderBy('id')->pluck('revoked_reason', 'id')->all();
    }
}
