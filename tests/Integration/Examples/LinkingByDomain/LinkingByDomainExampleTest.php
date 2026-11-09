<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\LinkingByDomain;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Validation\ValidationException;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/linking-by-domain.md` (SSO-8.8, SSO-12.5), on
 * the shared example harness, with the application's users, principals and
 * sessions in its own tables: its service provider binds the package's link
 * store and its own three linking contracts, which link a member's first
 * sign-in by their verified email where the defaults refused it, and refuse a
 * membership accepted no earlier than the domain's verification; an
 * administrator turns the connection's linking on for a shared issuer, which
 * then links only a result carrying the organisation's value, and invalid
 * settings come back as the application's validation errors, naming the setting
 * and the code; and granting a principal of another tenant, or a platform
 * principal, reports the widened scope first, which suspends the link for good
 * and revokes the session established through it, while a principal of the
 * connection's own tenant suspends nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkingPolicyService::class)]
#[CoversClass(ScopeWidening::class)]
final class LinkingByDomainExampleTest extends ExampleTestCase
{
    /** @var string The domain the tenant has verified for its connection. */
    private const string DOMAIN = 'example.com';

    /** @var string The person's verified email, of that domain. */
    private const string EMAIL = 'person@example.com';

    /** @var string Another tenant of the application. */
    private const string OTHER = 'tenant-2';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's identity provider, an issuer shared by organisations. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The member who signs in for the first time. */
    private IdentityReference $person;

    /** @var \SineMacula\Laravel\Sso\Identities\Caller The administrator who changes the connection. */
    private Caller $caller;

    /**
     * Switch domain linking on, create the application's tables with the
     * member, a member of the tenant for two days, make the tenant's OIDC
     * connection, and verify its domain.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.features.domain_linking', true);

        $schema = Schema::connection(StorageConnection::name());

        $schema->create(Users::TABLE, static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('email')->unique();
            $table->dateTime('email_verified_at')->nullable();
        });

        $schema->create(Users::PRINCIPALS, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('user_id');
            $table->string('tenant_id')->nullable();
            $table->dateTime('accepted_at')->nullable();
            $table->dateTime('revoked_at')->nullable();
        });

        $schema->create(RevokeLinkSessions::TABLE, static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('user_id');
            $table->string('tenant_id');
            $table->string('sso_connection_id')->nullable();
            $table->string('sso_link_id')->nullable();
            $table->dateTime('revoked_at')->nullable();
            $table->string('revoked_reason')->nullable();
        });

        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);
        $this->person       = new IdentityReference(Users::TYPE, 'person-1');
        $this->caller       = new Caller(new IdentityReference(Users::TYPE, 'admin-1'));

        $this->addMember('person-1', self::EMAIL, $this->clock->now()->subDays(2));

        $domains = app(DomainService::class);
        $claimed = $domains->claim(self::TENANT, $this->connectionId, self::DOMAIN, Clients::browser())->domain;

        self::assertNotNull($claimed);

        $this->dns->publishes($claimed);

        self::assertSame(DomainStatus::VERIFIED, $domains->verify(self::TENANT, $this->connectionId, self::DOMAIN, Clients::browser())->status);
    }

    /**
     * Drop the application's tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $schema = Schema::connection(StorageConnection::name());

        $schema->dropIfExists(RevokeLinkSessions::TABLE);
        $schema->dropIfExists(Users::PRINCIPALS);
        $schema->dropIfExists(Users::TABLE);

        parent::tearDown();
    }

    /**
     * Under the defaults, each of which refuses, a member's first sign-in with
     * their verified email reserves nothing and ends `unlinked`; once the
     * application's provider binds the link store and its contracts, the next
     * one reserves a link to the member that its admission activates.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheBindingsLinkAMembersFirstSignIn(): void
    {
        $this->turnLinkingOn();

        self::assertSame(FailureReason::UNLINKED->value, $this->refusal(self::EMAIL, self::DOMAIN));

        app()->register(AppServiceProvider::class);

        $signedIn = $this->signIn('session-1');

        self::assertTrue($signedIn->isRedeemed());
        self::assertEquals($this->person, $signedIn->linkedIdentity);
        self::assertNotNull($signedIn->linkId);
    }

    /**
     * A membership the person accepted at the domain's verification, not
     * strictly before it, is no membership for linking: the sign-in reserves
     * nothing and ends `unlinked`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAMembershipAcceptedSinceTheVerificationLinksNothing(): void
    {
        app()->register(AppServiceProvider::class);

        $this->turnLinkingOn();
        $this->addMember('person-2', 'newcomer@example.com', $this->clock->now());

        self::assertSame(FailureReason::UNLINKED->value, $this->refusal('newcomer@example.com', self::DOMAIN));
    }

    /**
     * Turning linking on for a shared issuer answers `updated`, naming each
     * setting that changed, and stores them under the first linking version; a
     * result carrying another organisation's value then reserves nothing, and
     * one carrying this organisation's links the member.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTurningLinkingOnForASharedIssuer(): void
    {
        app()->register(AppServiceProvider::class);

        $result = (new LinkingSettings)->enable(self::TENANT, $this->connectionId, self::DOMAIN, $this->caller);

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertNull($result->reason);
        self::assertSame(['linking.enabled', 'linking.issuer_class', 'linking.organization_claim', 'linking.organization_value'], $result->changedSettings);

        $settings = app(LinkingPolicyService::class)->get(self::TENANT, $this->connectionId);

        self::assertTrue($settings['enabled'] ?? null);
        self::assertSame('shared', $settings['issuer_class'] ?? null);
        self::assertSame('hd', $settings['organization_claim'] ?? null);
        self::assertSame(self::DOMAIN, $settings['organization_value'] ?? null);
        self::assertSame(1, $settings['version'] ?? null);

        self::assertSame(FailureReason::UNLINKED->value, $this->refusal(self::EMAIL, 'example.org'));
        self::assertEquals($this->person, $this->signIn('session-1')->linkedIdentity);
    }

    /**
     * A shared issuer with no organisation value is invalid, answered as the
     * application's validation error naming the setting and its code, and
     * changes nothing; a caller who did not authenticate recently enough is
     * refused `freshness_required` before anything is judged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInvalidSettingsAreTheApplicationsValidationErrors(): void
    {
        $settings = new LinkingSettings;

        try {
            $settings->enable(self::TENANT, $this->connectionId, null, $this->caller);

            self::fail('Settings with no organisation value were accepted.');
        } catch (ValidationException $invalid) {
            self::assertSame(['organization_value' => ['required']], $invalid->errors());
        }

        $this->freshness->staleFor(FreshnessOperation::CONNECTION_TRUST);

        $stale = $settings->enable(self::TENANT, $this->connectionId, self::DOMAIN, $this->caller);

        self::assertTrue($stale->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $stale->reason);

        $stored = app(LinkingPolicyService::class)->get(self::TENANT, $this->connectionId);

        self::assertFalse($stored['enabled'] ?? null);
        self::assertSame(0, $stored['version'] ?? null);
    }

    /**
     * Granting the linked member a principal of another tenant suspends the
     * link and revokes the session established through it, with the reason
     * `scope_widened`, in the transaction that writes the principal; the next
     * sign-in is `link_suspended`, and stays so once the principal is removed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testAPrincipalOfAnotherTenantSuspendsTheLinkForGood(): void
    {
        app()->register(AppServiceProvider::class);

        $this->turnLinkingOn();

        self::assertNotNull($this->signIn('session-1')->linkId);

        (new GrantPrincipal)($this->person, self::OTHER);

        self::assertSame(RevocationReason::SCOPE_WIDENED->value, $this->revocationOf('session-1'));
        self::assertSame(1, $this->principals()->where('tenant_id', self::OTHER)->count());
        self::assertSame(FailureReason::LINK_SUSPENDED->value, $this->refusal(self::EMAIL, self::DOMAIN));

        $this->principals()->where('tenant_id', self::OTHER)->delete();

        self::assertSame(FailureReason::LINK_SUSPENDED->value, $this->refusal(self::EMAIL, self::DOMAIN));
    }

    /**
     * A principal of the connection's own tenant leaves the link and its
     * session alone, and the member still signs in through it; a platform
     * principal, granted with no tenant, then suspends it and revokes the
     * session.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testOnlyAPrincipalOutsideTheTenantWidensTheScope(): void
    {
        app()->register(AppServiceProvider::class);

        $this->turnLinkingOn();
        $this->signIn('session-1');

        $grant = new GrantPrincipal;

        $grant($this->person, self::TENANT);

        self::assertNull($this->revocationOf('session-1'));
        self::assertEquals($this->person, $this->signIn('session-2')->linkedIdentity);

        $grant($this->person, null);

        self::assertSame(RevocationReason::SCOPE_WIDENED->value, $this->revocationOf('session-1'));
        self::assertSame(RevocationReason::SCOPE_WIDENED->value, $this->revocationOf('session-2'));
        self::assertSame(1, $this->principals()->whereNull('tenant_id')->count());
        self::assertSame(FailureReason::LINK_SUSPENDED->value, $this->refusal(self::EMAIL, self::DOMAIN));
    }

    /**
     * Turn the connection's linking on, its issuer shared and the tenant's
     * organisation holding the domain under `hd`.
     *
     * @return void
     */
    private function turnLinkingOn(): void
    {
        self::assertTrue((new LinkingSettings)->enable(self::TENANT, $this->connectionId, self::DOMAIN, $this->caller)->isChanged());
    }

    /**
     * Add a user with the verified email, holding a principal of the tenant the
     * person accepted at the instant given.
     *
     * @param  string  $id
     * @param  string  $email
     * @param  \Carbon\CarbonImmutable  $acceptedAt
     * @return void
     */
    private function addMember(string $id, string $email, CarbonImmutable $acceptedAt): void
    {
        $storage = DB::connection(StorageConnection::name());

        $storage->table(Users::TABLE)->insert(['id' => $id, 'email' => $email, 'email_verified_at' => $this->clock->now()->subYear()]);
        $storage->table(Users::PRINCIPALS)->insert(['user_id' => $id, 'tenant_id' => self::TENANT, 'accepted_at' => $acceptedAt]);
    }

    /**
     * Start a `sign_in` and have the provider answer it with the verified email
     * and the organisation's value under `hd`, delivering the answer to the
     * connection's completion endpoint.
     *
     * @param  string  $email
     * @param  string  $organization
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: \SineMacula\Laravel\Sso\Testing\HandoffRedirect}
     *
     * @throws \Random\RandomException
     */
    private function complete(string $email, string $organization): array
    {
        $tailor = static fn (FakeIdToken $token): FakeIdToken => $token->with('email', $email)->with('email_verified', true)->with('hd', $organization);
        $start  = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);

        return [$start, $this->respondAtProvider($this->provider, $this->connectionId, $start, $tailor)];
    }

    /**
     * The error the completion sent the browser back with, or `null` when it
     * issued a code.
     *
     * @param  string  $email
     * @param  string  $organization
     * @return ?string
     *
     * @throws \Random\RandomException
     */
    private function refusal(string $email, string $organization): ?string
    {
        return $this->complete($email, $organization)[1]->error;
    }

    /**
     * Sign the member in through the connection, admitting the code and
     * recording the session it establishes with the link it was established
     * through.
     *
     * @param  string  $sessionId
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Random\RandomException
     */
    private function signIn(string $sessionId): RedemptionResult
    {
        [$start, $redirect] = $this->complete(self::EMAIL, self::DOMAIN);

        self::assertNull($redirect->error);

        $signedIn = $this->admitSignIn($this->connectionId, $redirect, $start, $sessionId);

        self::assertNotNull($signedIn->linkedIdentity);

        DB::connection(StorageConnection::name())->table(RevokeLinkSessions::TABLE)->insert([
            'id'                => $sessionId,
            'user_id'           => $signedIn->linkedIdentity->id,
            'tenant_id'         => self::TENANT,
            'sso_connection_id' => $this->connectionId,
            'sso_link_id'       => $signedIn->linkId,
        ]);

        return $signedIn;
    }

    /**
     * Why the session was revoked, or `null` while it stands.
     *
     * @param  string  $sessionId
     * @return ?string
     */
    private function revocationOf(string $sessionId): ?string
    {
        $reason = DB::connection(StorageConnection::name())->table(RevokeLinkSessions::TABLE)->where('id', $sessionId)->value('revoked_reason');

        return is_string($reason) ? $reason : null;
    }

    /**
     * The query of the member's principals.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function principals(): Builder
    {
        return DB::connection(StorageConnection::name())->table(Users::PRINCIPALS)->where('user_id', $this->person->id);
    }
}
