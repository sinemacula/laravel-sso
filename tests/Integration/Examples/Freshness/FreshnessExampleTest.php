<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Freshness;

use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Freshness\MaximumAges;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/freshness.md` (SSO-2.12, SSO-12.5), on the
 * shared example harness: the guide's published maximum ages laid over the
 * package's and asked with each change; the application's own contract, bound
 * in its service provider in place of the default that refuses everything,
 * judging the caller of the request being served by the time they last
 * authenticated, from the session or a verified token, against the package's
 * clock; and `FakeFreshness` bound by a test, answering `stale` for one
 * operation and asserting what was asked. Each refusal is shown: a change asked
 * of a caller who authenticated too long ago, or in the future, or who cannot
 * be judged, is refused with `freshness_required` and writes nothing, and an
 * age out of range fails closed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeFreshness::class)]
#[CoversClass(FreshnessGate::class)]
#[CoversClass(MaximumAges::class)]
final class FreshnessExampleTest extends ExampleTestCase
{
    /** @var string The administrator the application has authenticated. */
    private const string ADMINISTRATOR = 'admin-1';

    /** @var string Where the application's administration takes a change. */
    private const string CHANGE_URL = 'https://app.example.com/admin/sso/connections';

    /**
     * Under the published configuration, a trust change is asked with the five
     * minutes it names, a key rotation with its two, and enabling a connection,
     * which it does not name, with the default.
     *
     * @return void
     */
    public function testThePublishedMaximumAgesAreAsked(): void
    {
        $this->publishConfiguration();

        $connectionId = $this->createConnection();

        self::assertTrue(app(KeyService::class)->addNext(self::TENANT, $connectionId, KeyUse::SP_SIGNING, Clients::browser())->isSucceeded());
        self::assertTrue(app(ConnectionService::class)->enable(self::TENANT, $connectionId, Clients::browser())->isChanged());

        $this->freshness->assertAsked(FreshnessOperation::CONNECTION_TRUST, 300);
        $this->freshness->assertAsked(FreshnessOperation::KEYS_ROTATE, 120);
        $this->freshness->assertAsked(FreshnessOperation::CONNECTION_ENABLE, 300);
    }

    /**
     * An administrator who signed in two hundred seconds ago may create and
     * enable a connection, but not rotate its keys, which the published
     * configuration holds to two minutes; once the package's clock has moved
     * past five minutes, they may not disable it either, and it stays enabled.
     *
     * @return void
     */
    public function testAKeyRotationRequiresTheShorterAge(): void
    {
        $this->publishConfiguration();

        app()->register(AppServiceProvider::class);

        $this->serveSession($this->clock->now()->getTimestamp() - 200);

        $connectionId = $this->createConnection();
        $rotated      = app(KeyService::class)->addNext(self::TENANT, $connectionId, KeyUse::SP_SIGNING, Clients::browser());

        self::assertTrue($rotated->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $rotated->reason);
        self::assertNull($rotated->key);
        self::assertTrue(app(ConnectionService::class)->enable(self::TENANT, $connectionId, Clients::browser())->isChanged());

        $this->clock->advance(101);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, app(ConnectionLifecycle::class)->disable(self::TENANT, $connectionId, Clients::browser())->reason);
        self::assertTrue(app(ConnectionService::class)->get(self::TENANT, $connectionId)?->enabled);
    }

    /**
     * A maximum age out of range fails closed, naming its key, when a change
     * reads it, rather than loosening what it was meant to require.
     *
     * @return void
     */
    public function testAnAgeOutOfRangeFailsClosed(): void
    {
        $connectionId = $this->createConnection();

        config()->set('sso.freshness.max_age_seconds.keys_rotate', 0);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('sso.freshness.max_age_seconds.keys_rotate must be an integer from 1 to 3600.');

        app(KeyService::class)->addNext(self::TENANT, $connectionId, KeyUse::SP_SIGNING, Clients::browser());
    }

    /**
     * The package's default answers `stale` for every operation; the
     * application's contract, bound by its service provider after the
     * package's, replaces it as the one contract the package asks.
     *
     * @return void
     */
    public function testTheApplicationsContractReplacesTheDefault(): void
    {
        app()->forgetInstance(Freshness::class);

        self::assertSame(FreshnessOutcome::STALE, app(Freshness::class)->check(FreshnessOperation::CONNECTION_ENABLE, 300));

        app()->register(AppServiceProvider::class);

        self::assertInstanceOf(RecentSignInFreshness::class, app(Freshness::class));
        self::assertSame(app(Freshness::class), app(Freshness::class));
    }

    /**
     * An administrator whose session records a sign-in exactly the maximum age
     * ago is fresh, and the connection is deleted.
     *
     * @return void
     */
    public function testASignInWithinTheMaximumAgeMayDeleteAConnection(): void
    {
        $connectionId = $this->createConnection();

        app()->register(AppServiceProvider::class);

        $this->serveSession($this->clock->now()->getTimestamp() - 300);

        self::assertTrue(app(ConnectionLifecycle::class)->delete(self::TENANT, $connectionId, Clients::browser())->isChanged());
        self::assertNull(app(ConnectionService::class)->get(self::TENANT, $connectionId));
    }

    /**
     * A second past the maximum age, the deletion is refused with
     * `freshness_required` and the connection is still there.
     *
     * @return void
     */
    public function testAStaleSignInIsRefusedAndNothingChanges(): void
    {
        $connectionId = $this->createConnection();

        app()->register(AppServiceProvider::class);

        $this->serveSession($this->clock->now()->getTimestamp() - 301);

        $deleted = app(ConnectionLifecycle::class)->delete(self::TENANT, $connectionId, Clients::browser());

        self::assertTrue($deleted->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $deleted->reason);
        self::assertNotNull(app(ConnectionService::class)->get(self::TENANT, $connectionId));
    }

    /**
     * On a request with no session, the contract reads the `auth_time` of the
     * verified token: one a minute old is fresh, and one in the future, which
     * the application cannot vouch for, is stale. Each question reads the
     * request then being served.
     *
     * @return void
     */
    public function testATokensAuthTimeIsJudgedWithoutASession(): void
    {
        $connectionId = $this->createConnection();
        $now          = $this->clock->now()->getTimestamp();

        app()->register(AppServiceProvider::class);

        $this->serveToken($now - 60);

        self::assertTrue(app(ConnectionService::class)->enable(self::TENANT, $connectionId, Clients::browser())->isChanged());

        $this->serveToken($now + 1);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, app(ConnectionLifecycle::class)->disable(self::TENANT, $connectionId, Clients::browser())->reason);
        self::assertTrue(app(ConnectionService::class)->get(self::TENANT, $connectionId)?->enabled);
    }

    /**
     * A caller the contract cannot judge is stale: one who is not signed in,
     * whatever their session holds, and one whose session records no sign-in,
     * or records it as anything but a timestamp.
     *
     * @return void
     */
    public function testACallerThatCannotBeJudgedIsStale(): void
    {
        $now = $this->clock->now()->getTimestamp();

        app()->register(AppServiceProvider::class);

        $this->serveSession($now - 10);

        $signedIn = app(Freshness::class)->check(FreshnessOperation::CONNECTION_DELETE, 300);

        $this->actingAsGuest();

        $signedOut = app(Freshness::class)->check(FreshnessOperation::CONNECTION_DELETE, 300);

        self::assertSame(FreshnessOutcome::FRESH, $signedIn);
        self::assertSame(FreshnessOutcome::STALE, $signedOut);

        foreach ([null, (string) ($now - 10), (float) ($now - 10)] as $recorded) {

            $this->serveSession($recorded);

            $unjudged = app(Freshness::class)->check(FreshnessOperation::CONNECTION_DELETE, 300);

            self::assertSame(FreshnessOutcome::STALE, $unjudged, sprintf('A session recording %s is stale.', var_export($recorded, true)));
        }
    }

    /**
     * `FakeFreshness` answers `stale` for the one operation it was told to, and
     * `fresh` for every other: the connection is enabled, its deletion is
     * refused, and the fake recorded each question with its maximum age.
     *
     * @return void
     */
    public function testTheFakeAnswersWhatTheTestTellsIt(): void
    {
        $connectionId = $this->createConnection();

        $client = Clients::browser();
        // @snippet-start fake-freshness
        $freshness = FakeFreshness::fresh()->staleFor(FreshnessOperation::CONNECTION_DELETE);

        $this->instance(Freshness::class, $freshness);

        self::assertTrue(app(ConnectionService::class)->enable(self::TENANT, $connectionId, $client)->isSucceeded());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, app(ConnectionLifecycle::class)->delete(self::TENANT, $connectionId, $client)->reason);

        $freshness->assertAsked(FreshnessOperation::CONNECTION_ENABLE, 300);
        $freshness->assertAskedExactly([FreshnessOperation::CONNECTION_ENABLE, FreshnessOperation::CONNECTION_DELETE]);
        // @snippet-end fake-freshness
        $freshness->assertNotAsked(FreshnessOperation::CONNECTION_TRUST);

        self::assertSame([
            ['operation' => FreshnessOperation::CONNECTION_ENABLE, 'max_age_seconds' => 300],
            ['operation' => FreshnessOperation::CONNECTION_DELETE, 'max_age_seconds' => 300],
        ], $freshness->asked());
        self::assertTrue(app(ConnectionService::class)->get(self::TENANT, $connectionId)?->enabled);
    }

    /**
     * Lay the guide's published configuration over the package's, key by key,
     * as Laravel merges a published file with a package's.
     *
     * @return void
     */
    private function publishConfiguration(): void
    {
        /** @var array<string, mixed> $published */
        $published = require __DIR__ . '/config/sso.php';

        /** @var array<string, mixed> $package */
        $package = config('sso');

        config()->set('sso', array_replace($package, $published));
    }

    /**
     * Create a disabled SAML connection of the tenant, and answer its id.
     *
     * @return string
     */
    private function createConnection(): string
    {
        $created = app(ConnectionService::class)->create(self::TENANT, 'saml2', 'Example SAML', Clients::browser(), [
            'idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID,
            'sso_url'       => FakeSamlIdentityProvider::SSO_URL,
        ]);

        self::assertTrue($created->isChanged());

        return (string) $created->connection?->id;
    }

    /**
     * Serve a request whose session records the administrator's sign-in at the
     * time given, as the application's sign-in stores it.
     *
     * @param  mixed  $authenticatedAt
     * @return void
     */
    private function serveSession(mixed $authenticatedAt): void
    {
        $session = new Store('example_session', new ArraySessionHandler(120));

        $session->put('auth.authenticated_at', $authenticatedAt);

        $request = Request::create(self::CHANGE_URL, 'POST');

        $request->setLaravelSession($session);

        $this->serve($request);
    }

    /**
     * Serve a request with no session, carrying the `auth_time` of the token
     * the application's middleware verified.
     *
     * @param  int  $authTime
     * @return void
     */
    private function serveToken(int $authTime): void
    {
        $request = Request::create(self::CHANGE_URL, 'POST');

        $request->attributes->set('auth_time', $authTime);

        $this->serve($request);
    }

    /**
     * Make the request the one being served, its caller the administrator.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    private function serve(Request $request): void
    {
        $this->instance('request', $request);

        $this->actingAs(new GenericUser(['id' => self::ADMINISTRATOR]));
    }
}
