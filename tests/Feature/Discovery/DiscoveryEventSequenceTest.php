<?php

declare(strict_types = 1);

namespace Tests\Feature\Discovery;

use Carbon\CarbonImmutable;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Protocols\StartingDriver;
use Tests\TestCase;

/**
 * The events a discovery start reports (SSO-3.5, SSO-10.1, SSO-10.2, SSO-10.4,
 * SSO-9.8): exactly `AuthorizationRequestStarted` for a match, with its whole
 * context; exactly one `FlowFailed(discovery_no_match)` for every kind of miss,
 * naming the application and the purpose alone; exactly one `FlowFailed` for
 * each refusal, with its reason; nothing for a misbound start; and never the
 * email, its domain, the protocol state, the nonce, a verifier or a challenge.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DiscoveryService::class)]
final class DiscoveryEventSequenceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The time every event is built at. */
    private const string OCCURRED_AT = '2026-11-01T09:30:00.000000Z';

    /** @var string The IP address every start comes from. */
    private const string IP = '203.0.113.7';

    /** @var string The user agent every start comes from. */
    private const string USER_AGENT = 'ExampleBrowser/1.0';

    /** @var string The local part of every email given. */
    private const string LOCAL_PART = 'jane.doe';

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract a `link` asks. */
    private RecordingFreshness $freshness;

    /** @var \Tests\Fixtures\Protocols\StartingDriver The driver the connections run over. */
    private StartingDriver $driver;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The usable connection `example.com` routes to. */
    private Connection $connection;

    /**
     * Bind a fixed clock, a freshness contract that answers `fresh` and a
     * request from the client, turn discovery on, register the applications and
     * the driver, create the tables, a usable connection and its verified
     * domain, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;
        $this->driver    = new StartingDriver;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, $this->freshness);
        $this->app?->instance('request', Request::create('/auth/sso/discovery', 'POST', server: [
            'REMOTE_ADDR'     => self::IP,
            'HTTP_USER_AGENT' => self::USER_AGENT,
        ]));

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.discovery', true);
        config()->set('sso.discovery.minimum_duration_milliseconds', 50);
        config()->set('sso.applications', [
            'web'         => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
            'discovering' => [
                'redirect_uri'     => 'https://app.example.com/sso',
                'external_sign_in' => true,
                'discovery'        => ['enabled' => true, 'fallback_url' => 'https://app.example.com/sign-in'],
            ],
        ]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(StartingDriver::NAME, fn (): StartingDriver => $driver);

        $this->createConnectionTables();
        $this->createDomainsTable();
        $this->createFlowTables();
        self::rateLimitsMigration()->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->usableConnection(['tenant_id' => 'tenant-7']);

        $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED]);

        $this->startRecordingEvents();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::rateLimitsMigration()->down(); // @phpstan-ignore method.notFound
        $this->dropFlowTables();
        $this->dropDomainsTable();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A match reports exactly `AuthorizationRequestStarted`, with the
     * connection, its tenant and protocol, the application, the purpose and the
     * public reference, and no failure; no event holds the email, its domain or
     * anything secret.
     *
     * @return void
     */
    public function testAMatchReportsStarted(): void
    {
        $result = $this->discover('example.com');

        $this->assertEventSequence([AuthorizationRequestStarted::class]);
        $this->assertNoFailure();

        self::assertSame($this->context([
            'connection_id'     => $this->connection->id,
            'tenant_id'         => 'tenant-7',
            'protocol'          => StartingDriver::NAME,
            'application'       => 'discovering',
            'purpose'           => 'sign_in',
            'request_reference' => $result->reference?->value,
        ]), $this->recordedEvents()[0]->context()->toArray());

        $this->assertNothingOfTheEmailIsShown('example.com');
        $this->assertNoSecretIn($result);
    }

    /**
     * Every kind of miss reports exactly one `discovery_no_match`, naming the
     * application and the purpose alone: no email, no domain, no connection and
     * no reference.
     *
     * @return void
     */
    public function testEachMissReportsExactlyOneNoMatch(): void
    {
        $lapsedAt = CarbonImmutable::parse('2026-10-31T09:30:00Z');
        $lapsesAt = CarbonImmutable::parse('2026-11-01T09:00:00Z');

        $this->makeDomain($this->usableConnection(['tenant_id' => 'tenant-8']), 'pending.com');
        $this->makeDomain($this->usableConnection(['tenant_id' => 'tenant-8']), 'lapsed.com', ['state' => DomainState::LAPSED, 'lapsed_at' => $lapsedAt]);
        $this->makeDomain($this->usableConnection(['tenant_id' => 'tenant-8']), 'past-grace.com', ['state' => DomainState::VERIFIED, 'lapses_at' => $lapsesAt]);
        $this->makeDomain($this->usableConnection(['tenant_id' => 'tenant-8', 'enabled' => false]), 'disabled.com', ['state' => DomainState::VERIFIED]);

        foreach (['unknown.com', 'pending.com', 'lapsed.com', 'past-grace.com', 'disabled.com'] as $domain) {

            $this->startRecordingEvents();

            $result = $this->discover($domain);

            self::assertTrue($result->isStarted(), $domain);

            $this->assertEventSequence([FlowFailed::class]);

            $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::DISCOVERY_NO_MATCH);

            self::assertSame($this->context(['application' => 'discovering', 'purpose' => 'sign_in']), $failure->context()->toArray(), $domain);

            $this->assertNothingOfTheEmailIsShown($domain);

            self::assertStringNotContainsString((string) $result->reference?->value, $this->shown());
            self::assertStringNotContainsString((string) $result->verifier?->reveal(), $this->shown());
        }

        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * A full limit reports one `rate_limited`, before any application is
     * admitted, and holds nothing of the email.
     *
     * @return void
     */
    public function testAFullLimitReportsOneFailure(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_email_domain', ['max' => 1, 'decay_seconds' => 60]);

        $this->discover('example.com');
        $this->startRecordingEvents();
        $this->discover('example.com');

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::RATE_LIMITED);

        self::assertSame($this->context(['purpose' => 'sign_in']), $failure->context()->toArray());

        $this->assertNothingOfTheEmailIsShown('example.com');
    }

    /**
     * An application that is not allowed reports one failure that names no
     * application.
     *
     * @return void
     */
    public function testAnApplicationThatIsNotAllowedReportsOneFailure(): void
    {
        $this->discover('example.com', application: 'missing');

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::APPLICATION_NOT_ALLOWED);

        self::assertSame($this->context(['purpose' => 'sign_in']), $failure->context()->toArray());
    }

    /**
     * An application that does not offer discovery reports one
     * `feature_disabled` that names the application.
     *
     * @return void
     */
    public function testAnApplicationThatDoesNotOfferDiscoveryReportsOneFailure(): void
    {
        $this->discover('example.com', application: 'web');

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::FEATURE_DISABLED);

        self::assertSame($this->context(['application' => 'web', 'purpose' => 'sign_in']), $failure->context()->toArray());
    }

    /**
     * A malformed challenge reports one failure that names the application,
     * never the challenge.
     *
     * @return void
     */
    public function testAMalformedChallengeReportsOneFailure(): void
    {
        $this->discover('example.com', codeChallenge: 'not-a-challenge');

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::CHALLENGE_INVALID);

        self::assertSame($this->context(['application' => 'discovering', 'purpose' => 'sign_in']), $failure->context()->toArray());
        self::assertStringNotContainsString('not-a-challenge', $this->shown());
    }

    /**
     * A stale `link` that matches reports one `freshness_required`, with the
     * connection and the identity.
     *
     * @return void
     */
    public function testAStaleLinkThatMatchesReportsOneFailure(): void
    {
        $this->freshness->answer(FreshnessOutcome::STALE);

        $this->discover('example.com', Purpose::LINK, identity: new IdentityReference('App\Models\User', '42'));

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::FRESHNESS_REQUIRED);

        self::assertSame($this->context([
            'connection_id'        => $this->connection->id,
            'tenant_id'            => 'tenant-7',
            'protocol'             => StartingDriver::NAME,
            'application'          => 'discovering',
            'purpose'              => 'link',
            'identity_morph_class' => 'App\Models\User',
            'identity_id'          => '42',
        ]), $failure->context()->toArray());
    }

    /**
     * A match whose connection is disabled while the driver starts reports one
     * `connection_unavailable`, and no `discovery_no_match`.
     *
     * @return void
     */
    public function testAMatchDisabledWhileStartingReportsOneFailure(): void
    {
        $connection = $this->connection;

        $this->driver->onStart = static function () use ($connection): void {
            $connection->forceFill(['enabled' => false])->save();
        };

        self::assertTrue($this->discover('example.com')->isStarted());

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::CONNECTION_UNAVAILABLE);
    }

    /**
     * A misbound start reports nothing: it is application code's mistake.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMisboundStartReportsNothing(): void
    {
        try {
            $this->discover('example.com', Purpose::LINK);
            self::fail('A misbound start was accepted.');
        } catch (\InvalidArgumentException) {
            $this->assertNoEvents();
        }
    }

    /**
     * Assert no event recorded holds the email, its local part or its domain.
     *
     * @param  string  $domain
     * @return void
     */
    private function assertNothingOfTheEmailIsShown(string $domain): void
    {
        $shown = $this->shown();

        self::assertNotSame('', $shown);
        self::assertStringNotContainsString(self::LOCAL_PART, $shown);
        self::assertStringNotContainsString($domain, $shown);
        self::assertStringNotContainsString('@', $shown);
    }

    /**
     * Assert nothing secret the start made is in any event recorded: not the
     * protocol state, the nonce, the PKCE verifier, the client's verifier, the
     * challenge or a digest.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $result
     * @return void
     */
    private function assertNoSecretIn(StartResult $result): void
    {
        $start = $this->driver->lastStart();
        $row   = AuthorizationRequest::query()->sole();
        $shown = $this->shown();

        $secrets = [
            $start->state->reveal(),
            $start->nonce?->reveal()        ?? '',
            $start->codeVerifier?->reveal() ?? '',
            $result->verifier?->reveal()    ?? '',
            $row->handoff_challenge,
            $row->state_digest,
            (string) $row->nonce_digest,
        ];

        foreach ($secrets as $secret) {
            self::assertNotSame('', $secret);
            self::assertStringNotContainsString($secret, $shown);
        }
    }

    /**
     * Every recorded event's context, as JSON.
     *
     * @return string
     */
    private function shown(): string
    {
        return (string) json_encode(array_map(static fn ($event): array => $event->context()->toArray(), $this->recordedEvents()), JSON_UNESCAPED_SLASHES);
    }

    /**
     * The whole context an event carries: the time and the client, the fields
     * given, and `null` for every other.
     *
     * @param  array<string, ?string>  $fields
     * @return array<string, ?string>
     */
    private function context(array $fields): array
    {
        return array_merge([
            'occurred_at'                 => self::OCCURRED_AT,
            'ip'                          => self::IP,
            'user_agent'                  => self::USER_AGENT,
            'connection_id'               => null,
            'tenant_id'                   => null,
            'protocol'                    => null,
            'application'                 => null,
            'purpose'                     => null,
            'request_reference'           => null,
            'identity_morph_class'        => null,
            'identity_id'                 => null,
            'acting_identity_morph_class' => null,
            'acting_identity_id'          => null,
            'principal_morph_class'       => null,
            'principal_id'                => null,
            'active_tenant_id'            => null,
            'session_id'                  => null,
            'method'                      => null,
        ], $fields);
    }

    /**
     * Start a flow by the email at the domain, a `sign_in` for `discovering`
     * unless told otherwise.
     *
     * @param  string  $domain
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Throwable
     */
    private function discover(
        string $domain,
        Purpose $purpose = Purpose::SIGN_IN,
        string $application = 'discovering',
        ?string $codeChallenge = null,
        ?IdentityReference $identity = null,
    ): StartResult {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DiscoveryService::class)->start($application, $purpose, self::LOCAL_PART . '@' . $domain, $codeChallenge, $identity);
    }

    /**
     * An enabled connection over the starting driver, complete unless told
     * otherwise.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function usableConnection(array $attributes = []): Connection
    {
        return $this->makeConnection($attributes + [
            'protocol' => StartingDriver::NAME,
            'enabled'  => true,
            'settings' => ['issuer' => 'https://idp.example.com'],
        ]);
    }

    /**
     * The shipped migration of the rate limit counters.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function rateLimitsMigration(): Migration
    {
        return require dirname(__DIR__, 3) . self::RATE_LIMITS_MIGRATION;
    }
}
