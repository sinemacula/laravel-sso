<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Freshness;

use Illuminate\Auth\GenericUser;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Freshness\MaximumAges;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
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
 * judging the caller it is given by the time the session they are on last
 * authenticated, as the application recorded it, against the package's clock;
 * and `FakeFreshness` bound by a test, answering `stale` for one operation and
 * asserting what was asked. Each refusal is shown: a change asked of a caller
 * who authenticated too long ago, or in the future, or who cannot be judged, is
 * refused with `freshness_required` and writes nothing, and an age out of range
 * fails closed.
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

        $caller = $this->signIn($this->clock->now()->getTimestamp() - 200);

        $connectionId = $this->createConnection($caller);
        $rotated      = app(KeyService::class)->addNext(self::TENANT, $connectionId, KeyUse::SP_SIGNING, Clients::browser(), caller: $caller);

        self::assertTrue($rotated->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $rotated->reason);
        self::assertNull($rotated->key);
        self::assertTrue(app(ConnectionService::class)->enable(self::TENANT, $connectionId, Clients::browser(), $caller)->isChanged());

        $this->clock->advance(101);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, app(ConnectionLifecycle::class)->disable(self::TENANT, $connectionId, Clients::browser(), $caller)->reason);
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

        self::assertSame(FreshnessOutcome::STALE, app(Freshness::class)->check(FreshnessOperation::CONNECTION_ENABLE, 300, null));

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

        $caller = $this->signIn($this->clock->now()->getTimestamp() - 300);

        self::assertTrue(app(ConnectionLifecycle::class)->delete(self::TENANT, $connectionId, Clients::browser(), $caller)->isChanged());
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

        $caller  = $this->signIn($this->clock->now()->getTimestamp() - 301);
        $deleted = app(ConnectionLifecycle::class)->delete(self::TENANT, $connectionId, Clients::browser(), $caller);

        self::assertTrue($deleted->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $deleted->reason);
        self::assertNotNull(app(ConnectionService::class)->get(self::TENANT, $connectionId));
    }

    /**
     * A sign-in a minute old is fresh, and one recorded in the future, which
     * the application cannot vouch for, is stale. Each question judges the
     * caller it is given.
     *
     * @return void
     */
    public function testASignInInTheFutureIsStale(): void
    {
        $connectionId = $this->createConnection();
        $now          = $this->clock->now()->getTimestamp();

        app()->register(AppServiceProvider::class);

        self::assertTrue(app(ConnectionService::class)->enable(self::TENANT, $connectionId, Clients::browser(), $this->signIn($now - 60))->isChanged());

        $future = $this->signIn($now + 1, 'session-2');

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, app(ConnectionLifecycle::class)->disable(self::TENANT, $connectionId, Clients::browser(), $future)->reason);
        self::assertTrue(app(ConnectionService::class)->get(self::TENANT, $connectionId)?->enabled);
    }

    /**
     * A caller the contract cannot judge is stale: no caller, a caller on no
     * session, a caller on a session no sign-in was recorded for, and one on
     * another identity's session, however recent.
     *
     * @return void
     */
    public function testACallerThatCannotBeJudgedIsStale(): void
    {
        $now = $this->clock->now()->getTimestamp();

        app()->register(AppServiceProvider::class);

        $signedIn = $this->signIn($now - 10);
        $identity = $signedIn->identity;

        self::assertSame(FreshnessOutcome::FRESH, app(Freshness::class)->check(FreshnessOperation::CONNECTION_DELETE, 300, $signedIn));

        $unjudged = [
            'no caller'               => null,
            'no session'              => new Caller($identity),
            'an unknown session'      => new Caller($identity, 'session-unknown'),
            'another identity\'s one' => new Caller(new IdentityReference(GenericUser::class, 'someone-else'), 'session-1'),
        ];

        foreach ($unjudged as $case => $caller) {
            self::assertSame(
                FreshnessOutcome::STALE,
                app(Freshness::class)->check(FreshnessOperation::CONNECTION_DELETE, 300, $caller),
                sprintf('A caller with %s is stale.', $case),
            );
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
            ['operation' => FreshnessOperation::CONNECTION_ENABLE, 'max_age_seconds' => 300, 'caller' => null],
            ['operation' => FreshnessOperation::CONNECTION_DELETE, 'max_age_seconds' => 300, 'caller' => null],
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
     * Create a disabled SAML connection of the tenant, for the caller given,
     * and answer its id.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return string
     */
    private function createConnection(?Caller $caller = null): string
    {
        $created = app(ConnectionService::class)->create(self::TENANT, 'saml2', 'Example SAML', Clients::browser(), [
            'idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID,
            'sso_url'       => FakeSamlIdentityProvider::SSO_URL,
        ], caller: $caller);

        self::assertTrue($created->isChanged());

        return (string) $created->connection?->id;
    }

    /**
     * Record the administrator's sign-in on the session at the time given, as
     * the application's sign-in records it, and answer them as the caller the
     * application gives the package: their identity, on that session.
     *
     * @param  int  $authenticatedAt
     * @param  string  $sessionId
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    private function signIn(int $authenticatedAt, string $sessionId = 'session-1'): Caller
    {
        $identity = new IdentityReference(GenericUser::class, self::ADMINISTRATOR);

        app(SignInTimes::class)->record($identity, $sessionId, $authenticatedAt);

        return new Caller($identity, $sessionId);
    }
}
