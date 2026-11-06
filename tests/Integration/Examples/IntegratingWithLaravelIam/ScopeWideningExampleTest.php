<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Integration\Examples\Application\ExampleDirectory;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The scope-widening example of `docs/guides/integrating-with-laravel-iam.md`
 * (SSO-8.8, SSO-12.5), on the shared example harness: a person linked by the
 * tenant's verified domain is given a principal through the application's
 * principal change, which calls `widened()` first, then takes its principal
 * guard and writes the principal, in one transaction on the storage connection.
 *
 * A principal of another tenant suspends the person's verified domain link and
 * revokes the sessions established through it, with the reason `scope_widened`,
 * committing with the principal; one of the link's own tenant changes nothing
 * of the link's. Reported outside a transaction, the widening is refused and
 * writes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ScopeWidening::class)]
final class ScopeWideningExampleTest extends ExampleTestCase
{
    /** @var string Another tenant of the application. */
    private const string OTHER_TENANT = 'tenant-2';

    /** @var string The person's verified email, at the tenant's verified domain. */
    private const string EMAIL = 'person@example.com';

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /** @var \Tests\Integration\Examples\IntegratingWithLaravelIam\RecordedRevocations The application's session revocation. */
    private RecordedRevocations $revocations;

    /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\LinkSuspended> Each suspension reported. */
    private \ArrayObject $suspended;

    /**
     * Create the application's principal tables, bind its directory and its
     * revocation, and link the person by the tenant's verified domain.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $schema = Schema::connection(StorageConnection::name());

        $schema->create(Principals::TABLE, static function (Blueprint $table): void {
            $table->id();
            $table->string('identity_type');
            $table->string('identity_id');
            $table->string('tenant_id')->nullable();
        });

        $schema->create(Principals::GUARDS, static function (Blueprint $table): void {
            $table->string('identity_type');
            $table->string('identity_id');
            $table->primary(['identity_type', 'identity_id']);
        });

        $this->person      = new IdentityReference('App\Models\User', 'person-1');
        $this->revocations = new RecordedRevocations;
        $this->suspended   = new \ArrayObject;

        $this->instance(SessionRevocation::class, $this->revocations);

        $suspended = $this->suspended;

        Event::listen(LinkSuspended::class, static function (LinkSuspended $event) use ($suspended): void {
            $suspended->append($event);
        });

        $this->linkByVerifiedDomain();
    }

    /**
     * Drop the application's principal tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $schema = Schema::connection(StorageConnection::name());

        $schema->dropIfExists(Principals::GUARDS);
        $schema->dropIfExists(Principals::TABLE);

        parent::tearDown();
    }

    /**
     * A principal of another tenant suspends the person's verified domain link,
     * reported once, and revokes the sessions established through that link, by
     * the link, with the reason `scope_widened`; the principal is written with
     * them.
     *
     * @return void
     */
    public function testAPrincipalOfAnotherTenantSuspendsTheDomainLink(): void
    {
        $linkId = $this->domainLink()->id;

        self::changePrincipals(['identity' => $this->person, 'tenant' => self::OTHER_TENANT]);

        self::assertSame(LinkState::SUSPENDED, $this->domainLink()->state);
        self::assertCount(1, $this->suspended);
        self::assertCount(1, $this->revocations->revoked());

        $revoked = $this->revocations->revoked()[0];

        self::assertSame(RevocationScopeKind::IDENTITY_LINK, $revoked->kind);
        self::assertSame(RevocationReason::SCOPE_WIDENED, $revoked->reason);
        self::assertSame($linkId, $revoked->linkId);
        self::assertTrue($revoked->identity?->is($this->person));
        self::assertSame([self::OTHER_TENANT], app(Principals::class)->tenantsOf($this->person));
    }

    /**
     * A principal of the link's own tenant is inside it: the link stays active,
     * nothing is revoked, and the principal is written.
     *
     * @return void
     */
    public function testAPrincipalOfTheLinksOwnTenantChangesNothing(): void
    {
        self::changePrincipals(['identity' => $this->person, 'tenant' => self::TENANT]);

        self::assertSame(LinkState::ACTIVE, $this->domainLink()->state);
        self::assertCount(0, $this->suspended);
        self::assertSame([], $this->revocations->revoked());
        self::assertSame([self::TENANT], app(Principals::class)->tenantsOf($this->person));
    }

    /**
     * Reported with no transaction open on the storage connection, the widening
     * is a `LogicException`, and suspends and revokes nothing.
     *
     * @return void
     */
    public function testAWideningOutsideATransactionIsRefused(): void
    {
        try {
            app(ScopeWidening::class)->widened($this->person, self::OTHER_TENANT, Clients::browser());
            self::fail('The widening was reported outside a transaction.');
        } catch (\LogicException $refused) {
            self::assertStringContainsString('inside the transaction', $refused->getMessage());
        }

        self::assertSame(LinkState::ACTIVE, $this->domainLink()->state);
        self::assertSame([], $this->revocations->revoked());
    }

    /**
     * Run the application's principal change, as its principal mutation does,
     * given the person and the new principal's tenant.
     *
     * @param  array<string, mixed>  $change
     * @return void
     */
    private static function changePrincipals(array $change): void
    {
        require __DIR__ . '/principals/scope-widening.php';
    }

    /**
     * The person's one link, by the verified domain.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkSummary
     */
    private function domainLink(): LinkSummary
    {
        $links = app(LinkService::class)->list($this->person);

        self::assertCount(1, $links);
        self::assertTrue($links[0]->domainProvenance);

        return $links[0];
    }

    /**
     * Verify the tenant's domain for an OpenID connection, turn linking by it
     * on, and sign the person in by their verified email, which reserves the
     * link that the redemption activates.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function linkByVerifiedDomain(): void
    {
        config()->set('sso.features.domain_linking', true);

        $directory = new ExampleDirectory;

        $directory->add($this->person, self::EMAIL, self::TENANT, $this->clock->now()->subDays(2));

        $this->instance(LinkEmailMatcher::class, $directory);
        $this->instance(PrincipalScope::class, $directory);
        $this->instance(TenantMembership::class, $directory);

        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);
        $domains      = app(DomainService::class);
        $claimed      = $domains->claim(self::TENANT, $connectionId, 'example.com', Clients::browser())->domain;

        self::assertNotNull($claimed);

        $this->dns->publishes($claimed);

        self::assertSame(DomainStatus::VERIFIED, $domains->verify(self::TENANT, $connectionId, 'example.com', Clients::browser())->status);
        self::assertTrue(app(LinkingPolicyService::class)->change(self::TENANT, $connectionId, [
            'enabled'      => true,
            'issuer_class' => 'single_organization',
            'acknowledged' => true,
        ], Clients::browser())->isChanged());

        $withEmail = static fn (FakeIdToken $token): FakeIdToken => $token->with('email', self::EMAIL)->with('email_verified', true);
        $start     = $this->startFlow(Purpose::SIGN_IN, $connectionId);
        $redirect  = $this->respondAtProvider($provider, $connectionId, $start, $withEmail);

        self::assertTrue($this->admitSignIn($connectionId, $redirect, $start, 'session-1')->linkedIdentity?->is($this->person));
    }
}
