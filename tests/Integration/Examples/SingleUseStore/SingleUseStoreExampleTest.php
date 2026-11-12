<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SingleUseStore;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeServiceProvider;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/single-use-store.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseSingleUseStore::class)]
final class SingleUseStoreExampleTest extends ExampleTestCase
{
    /** @var string A key that is a secret, which no refusal may hold. */
    private const string SECRET = 'invitation-secret-7f3a9c';

    /** @var \Tests\Integration\Examples\SingleUseStore\Invitations The application's invitations. */
    private Invitations $invitations;

    /**
     * Make two open invitations and one closed, and create the keys table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->invitations = new Invitations($this->clock, [
            'token-a'      => $this->clock->now()->addDays(7),
            'token-b'      => $this->clock->now()->addDays(7),
            'token-closed' => $this->clock->now()->subSecond(),
        ]);

        Schema::connection(StorageConnection::name())->create(ApplicationSingleUseStore::TABLE, static function (Blueprint $table): void {
            $table->string('namespace', 64);
            $table->char('key_digest', 64);
            $table->string('expires_at', 26);
            $table->primary(['namespace', 'key_digest']);
        });
    }

    /**
     * Drop the application's keys table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::connection(StorageConnection::name())->dropIfExists(ApplicationSingleUseStore::TABLE);

        parent::tearDown();
    }

    /**
     * An open invitation is accepted once, across requests.
     *
     * @return void
     */
    public function testAnInvitationIsAcceptedOnce(): void
    {
        $accepted = $this->accept('token-a');

        self::assertSame(200, $accepted->getStatusCode());
        self::assertSame(['accepted' => true], $accepted->getData(true));

        $again = $this->accept('token-a');

        self::assertSame(409, $again->getStatusCode());
        self::assertSame(['error' => 'invitation_used'], $again->getData(true));

        app()->forgetScopedInstances();

        self::assertSame(409, $this->accept('token-a')->getStatusCode());
        self::assertSame(200, $this->accept('token-b')->getStatusCode());
    }

    /**
     * A closed or unknown invitation is not found, and never reaches the store.
     *
     * @return void
     */
    public function testAClosedOrUnknownInvitationIsNotFound(): void
    {
        foreach (['token-closed', 'token-unknown'] as $token) {

            $answer = $this->accept($token);

            self::assertSame(404, $answer->getStatusCode());
            self::assertSame(['error' => 'invitation_not_found'], $answer->getData(true));
        }
    }

    /**
     * A key is held until its expiry, then released by its next record.
     *
     * @return void
     */
    public function testAKeyIsReleasedOnceItsExpiryHasPassed(): void
    {
        $store = app(SingleUseStore::class);

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('invitation', self::SECRET, $this->clock->now()->addSeconds(60)));

        $this->clock->advance(59);

        self::assertSame(SingleUseOutcome::SEEN, $store->record('invitation', self::SECRET, $this->clock->now()->addSeconds(60)));

        $this->clock->advance(1);

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('invitation', self::SECRET, $this->clock->now()->addSeconds(60)));
    }

    /**
     * Both stores refuse a malformed record without revealing the key.
     *
     * @return void
     */
    public function testAMalformedRecordIsRefusedWithoutTheKey(): void
    {
        $now     = $this->clock->now();
        $records = [
            ['Invitation', self::SECRET, $now->addMinute()],
            ['invitation', '', $now->addMinute()],
            ['invitation', self::SECRET, $now],
        ];

        foreach ([app(SingleUseStore::class), new ApplicationSingleUseStore($this->clock)] as $store) {
            foreach ($records as [$namespace, $key, $until]) {
                self::assertStringNotContainsString(self::SECRET, self::refusalOf($store, $namespace, $key, $until));
            }
        }

        self::assertSame([], self::heldNamespaces());
    }

    /**
     * The application's store is bound once per request or job.
     *
     * @return void
     */
    public function testTheApplicationsStoreIsBoundScoped(): void
    {
        app()->register(AppServiceProvider::class);

        $store = app(SingleUseStore::class);

        self::assertInstanceOf(ApplicationSingleUseStore::class, $store);
        self::assertSame($store, app(SingleUseStore::class));

        app()->forgetScopedInstances();

        self::assertInstanceOf(ApplicationSingleUseStore::class, app(SingleUseStore::class));
        self::assertNotSame($store, app(SingleUseStore::class));
    }

    /**
     * A `link` flow records its request and handoff code as SHA-256 digests.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheApplicationsStoreRecordsTheFlowsKeys(): void
    {
        app()->register(AppServiceProvider::class);

        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);

        $this->linkThroughFlow($provider, $connectionId, new IdentityReference('App\Models\User', 'person-1'));

        self::assertSame(['authorization_request', 'handoff_code'], self::heldNamespaces());

        foreach (self::held()->pluck('key_digest') as $digest) {
            self::assertIsString($digest);
            self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $digest);
        }
    }

    /**
     * The application's store refuses a replayed SAML response as `replayed`.
     *
     * @return void
     */
    public function testTheApplicationsStoreRefusesAReplayedAssertion(): void
    {
        app()->register(AppServiceProvider::class);

        config()->set('sso.features.idp_initiated', true);

        $idp          = new FakeSamlIdentityProvider;
        $connectionId = $this->makeSamlConnection($idp, ['idp_initiated' => true, 'idp_initiated_start_url' => 'https://app.example.com/sso/start']);
        $metadata     = app(ServiceProviderDescriptions::class)->describe(self::TENANT, $connectionId);
        $sp           = FakeServiceProvider::fromMetadata((string) $metadata->body);
        $unsolicited  = $idp->response($sp->entityId, $sp->assertionConsumerService, $this->clock->now());
        $completions  = app(CompletionService::class);

        self::assertTrue(
            $completions->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $connectionId, $unsolicited->completionRequest(), Clients::browser())->isReinitiated(),
        );
        self::assertSame(['saml_assertion'], self::heldNamespaces());

        $replayed = $completions->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $connectionId, $unsolicited->completionRequest(), Clients::browser());

        self::assertTrue($replayed->isRejected());
        self::assertSame(FailureReason::REPLAYED, $replayed->reason);
        self::assertSame(['saml_assertion'], self::heldNamespaces());
    }

    /**
     * Present the token to the guide's invitation acceptance.
     *
     * @param  string  $token
     * @return \Illuminate\Http\JsonResponse
     */
    private function accept(string $token): JsonResponse
    {
        $answer = self::atAcceptance(['token' => $token, 'invitations' => $this->invitations]);

        self::assertInstanceOf(JsonResponse::class, $answer);

        return $answer;
    }

    /**
     * Run the guide's invitation acceptance with its input in scope.
     *
     * @param  array{token: string, invitations: \Tests\Integration\Examples\SingleUseStore\Invitations}  $input
     * @return mixed
     */
    private static function atAcceptance(array $input): mixed
    {
        return require __DIR__ . '/accept-invitation.php';
    }

    /**
     * The message the store refuses the record with.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SingleUseStore  $store
     * @param  string  $namespace
     * @param  string  $key
     * @param  \Carbon\CarbonImmutable  $until
     * @return string
     *
     * @throws \Throwable
     */
    private static function refusalOf(SingleUseStore $store, string $namespace, string $key, CarbonImmutable $until): string
    {
        try {
            $store->record($namespace, $key, $until);
        } catch (\InvalidArgumentException $exception) {
            return $exception->getMessage();
        }

        return self::fail("The store recorded a key in {$namespace} it should have refused.");
    }

    /**
     * The namespace of each key the application's store holds, in order.
     *
     * @return list<string>
     */
    private static function heldNamespaces(): array
    {
        /** @var list<string> */
        return self::held()->orderBy('namespace')->pluck('namespace')->all();
    }

    /**
     * The application's keys table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function held(): Builder
    {
        return DB::connection(StorageConnection::name())->table(ApplicationSingleUseStore::TABLE);
    }
}
