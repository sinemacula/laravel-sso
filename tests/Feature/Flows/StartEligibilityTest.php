<?php

declare(strict_types = 1);

namespace Tests\Feature\Flows;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Flows\StartEligibility;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\TestCase;

/**
 * Feature tests for whether a purpose may start through a connection (steps 6
 * and 7 of a start): a `sign_in` always may and asks nothing; a `link` asks the
 * freshness contract for `sso.link.create`; a `reauthenticate` asks the session
 * contract whether the identity is signed in through the connection on the
 * session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StartEligibility::class)]
final class StartEligibilityTest extends TestCase
{
    use UsesConnections;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract a `link` asks. */
    private RecordingFreshness $freshness;

    /** @var \Tests\Fixtures\Linking\RecordingSessions The session contract a `reauthenticate` asks. */
    private RecordingSessions $sessions;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the purpose starts through. */
    private Connection $connection;

    /**
     * Bind the recording contracts and create the connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;
        $this->sessions  = new RecordingSessions;

        $this->app?->instance(Freshness::class, $this->freshness);
        $this->app?->instance(ReauthenticationSessions::class, $this->sessions);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['enabled' => true]);
    }

    /**
     * A `sign_in` may always start, asking neither contract.
     *
     * @return void
     */
    public function testASignInMayAlwaysStart(): void
    {
        self::assertNull($this->eligibility()->refusal(Purpose::SIGN_IN, $this->connection, null));
        self::assertSame([], $this->freshness->asked());
    }

    /**
     * A `link` may start once the freshness contract answers `fresh` for
     * `sso.link.create`, asked for the caller as given, its session included,
     * and is `freshness_required` when it answers `stale`.
     *
     * @return void
     */
    public function testALinkNeedsAFreshAuthentication(): void
    {
        $caller = new Caller(new IdentityReference('App\Models\User', '7'), 'session-1');

        self::assertNull($this->eligibility()->refusal(Purpose::LINK, $this->connection, $caller));
        self::assertSame([FreshnessOperation::LINK_CREATE], $this->freshness->operations());
        self::assertSame([$caller], $this->freshness->callers());

        $this->freshness->answer(FreshnessOutcome::STALE);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $this->eligibility()->refusal(Purpose::LINK, $this->connection, $caller));
    }

    /**
     * A `reauthenticate` may start once the identity is signed in through the
     * connection on the session, and is `session_ineligible` otherwise; the
     * freshness contract is never asked.
     *
     * @return void
     */
    public function testAReauthenticationNeedsTheIdentitySignedInOnTheSession(): void
    {
        $caller = new Caller(new IdentityReference('App\Models\User', '7'), 'session-1');

        self::assertNull($this->eligibility()->refusal(Purpose::REAUTHENTICATE, $this->connection, $caller));

        $this->sessions->standing = SessionStanding::NOT_SIGNED_IN;

        self::assertSame(FailureReason::SESSION_INELIGIBLE, $this->eligibility()->refusal(Purpose::REAUTHENTICATE, $this->connection, $caller));
        self::assertSame([], $this->freshness->asked());
    }

    /**
     * The eligibility, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Flows\StartEligibility
     */
    private function eligibility(): StartEligibility
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(StartEligibility::class);
    }
}
