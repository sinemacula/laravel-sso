<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Provisioning;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/provisioning.md` (SSO-8.6, SSO-12.5), on the
 * shared example harness, with the application's users and memberships in its
 * own tables on the package's storage connection and its listener registered by
 * its service provider: a `sign_in` of a subject nobody is linked to is offered
 * to the listener, which creates a new user and their membership and links the
 * result to them, and the same sign-in completes for that user, as does their
 * next one, through the link; a listener whose helper refuses, here because a
 * slower listener before it let the verified response's deadline pass, rolls
 * the user and membership back, and the sign-in fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProvisioningHelper::class)]
#[CoversClass(ResultUnlinked::class)]
final class ProvisioningListenerExampleTest extends ExampleTestCase
{
    /** @var int How long a verified response stays valid, in seconds, by default. */
    private const int VERIFIED_RESULT_MAX_AGE = 120;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's identity provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var list<\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin> The origin of every link created, in order. */
    private array $origins = [];

    /**
     * Create the application's tables, make the tenant's OIDC connection, and
     * record the origin of every link created.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $schema = Schema::connection(StorageConnection::name());

        $schema->create(User::TABLE, static function (Blueprint $table): void {
            $table->id();
            $table->string('name');
        });

        $schema->create(Membership::TABLE, static function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id');
            $table->string('tenant_id');
        });

        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);

        Event::listen(LinkCreated::class, function (LinkCreated $event): void {
            $this->origins[] = $event->origin;
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
        $schema = Schema::connection(StorageConnection::name());

        $schema->dropIfExists(Membership::TABLE);
        $schema->dropIfExists(User::TABLE);

        parent::tearDown();
    }

    /**
     * The listener creates a new user named by the mapped display name, their
     * membership of the connection's tenant and an active link made by
     * provisioning, and the sign-in completes for that user; their next sign-in
     * resolves through the link, and provisions nobody.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheListenerProvisionsANewPersonAndTheSignInCompletes(): void
    {
        app()->register(AppServiceProvider::class);

        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start, self::named('Ada Person'));
        $signedIn = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

        $user     = User::query()->sole();
        $identity = new IdentityReference($user->getMorphClass(), (string) $user->getKey());

        self::assertTrue($signedIn->isAdmitted());
        self::assertSame('Ada Person', $user->name);
        self::assertSame([self::TENANT], $user->memberships()->pluck('tenant_id')->all());
        self::assertEquals($identity, $signedIn->linkedIdentity);
        self::assertSame([LinkOrigin::PROVISIONING], $this->origins);

        $links = app(LinkService::class)->list($identity);

        self::assertCount(1, $links);
        self::assertSame($signedIn->linkId, $links[0]->id);
        self::assertSame(LinkState::ACTIVE, $links[0]->state);

        $again = $this->signInThroughFlow($this->provider, $this->connectionId, 'session-2');

        self::assertTrue($again->isAdmitted());
        self::assertEquals($identity, $again->linkedIdentity);
        self::assertSame($signedIn->linkId, $again->linkId);
        self::assertSame(1, User::query()->count());
        self::assertSame([LinkOrigin::PROVISIONING], $this->origins);
    }

    /**
     * A listener before the provisioning one takes until the verified
     * response's deadline, so the helper refuses it as expired: the listener
     * rolls its user and membership back, no link is made, and the sign-in
     * fails with `request_expired`, never with a handoff.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusedLinkRollsTheNewPersonBack(): void
    {
        Event::listen(ResultUnlinked::class, function (): void {
            $this->clock->advance(self::VERIFIED_RESULT_MAX_AGE);
        });

        app()->register(AppServiceProvider::class);

        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start, self::named('Ada Person'));

        self::assertFalse($redirect->hasCode());
        self::assertSame(FailureReason::REQUEST_EXPIRED->value, $redirect->error);
        self::assertSame(0, User::query()->count());
        self::assertSame(0, Membership::query()->count());
        self::assertSame([], $this->origins);
    }

    /**
     * A tailor that gives the ID token the person's name, which the connection
     * maps to `display_name` by default.
     *
     * @param  string  $name
     * @return \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken
     */
    private static function named(string $name): \Closure
    {
        return static fn (FakeIdToken $token): FakeIdToken => $token->with('name', $name);
    }
}
