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
 * Integration tests for the provisioning guide's listener.
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
    /** @var int The default verified result lifetime, in seconds. */
    private const int VERIFIED_RESULT_MAX_AGE = 120;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's identity provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts the provider. */
    private string $connectionId;

    /** @var list<\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin> The origin of each link created, in order. */
    private array $origins = [];

    /**
     * Create the application's tables and the tenant's OIDC connection.
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
     * The listener provisions a new person, and their next sign-in uses the
     * link.
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
     * A refusal past the verified result's deadline rolls the new person back.
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
     * A tailor giving the ID token a name, mapped to `display_name` by default.
     *
     * @param  string  $name
     * @return \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken
     */
    private static function named(string $name): \Closure
    {
        return static fn (FakeIdToken $token): FakeIdToken => $token->with('name', $name);
    }
}
