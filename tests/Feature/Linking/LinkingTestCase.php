<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Carbon\CarbonImmutable;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Http\Request;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Linking\ScriptedEmailMatcher;
use Tests\Fixtures\Linking\ScriptedLinkConfirmation;
use Tests\Fixtures\Linking\ScriptedPrincipalScope;
use Tests\Fixtures\Linking\ScriptedTenantMembership;
use Tests\Fixtures\Protocols\StartingDriver;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * What every test of the linking state machine stands on
 * (`docs/design/linking.md`): the public flow from start, through completion,
 * to redemption, over a driver that verifies what the test sets; the package's
 * link store bound as the linker; a connection with linking by a verified
 * domain on and classified single organisation; its verified claim of
 * `example.com`, last checked now; and scripted contracts that accept the
 * person: a sole email match, a scope within the tenant, a membership accepted
 * a day before the domain's verification, and a caller authenticated apart from
 * any verified domain link. A test withdraws one condition at a time.
 *
 * It is the test infrastructure BL-60 to BL-64 build their adversarial tests
 * on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class LinkingTestCase extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The linking email the driver verifies, exactly as asserted. */
    protected const string EMAIL = 'Person@Example.COM';

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    protected FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection, usable, with linking on. */
    protected Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\Domain The connection's verified claim of `example.com`. */
    protected Domain $domain;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity the email matches. */
    protected IdentityReference $person;

    /** @var \Tests\Fixtures\Linking\ScriptedEmailMatcher The link email contract. */
    protected ScriptedEmailMatcher $matcher;

    /** @var \Tests\Fixtures\Linking\ScriptedPrincipalScope The principal scope contract. */
    protected ScriptedPrincipalScope $scope;

    /** @var \Tests\Fixtures\Linking\ScriptedTenantMembership The tenant membership contract. */
    protected ScriptedTenantMembership $membership;

    /** @var \Tests\Fixtures\Linking\ScriptedLinkConfirmation The link confirmation contract. */
    protected ScriptedLinkConfirmation $confirmation;

    /** @var \Tests\Fixtures\Protocols\VerifyingDriver The driver, which verifies what the test sets. */
    protected VerifyingDriver $verifying;

    /** @var \Tests\Fixtures\Protocols\StartingDriver The driver that records each start, and its state. */
    protected StartingDriver $starting;

    /**
     * Bind the clock, the store and the scripted contracts, turn the feature on
     * and create the tables, the connection and its claim.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock     = new FixedClock('2026-11-01T09:30:00Z');
        $this->starting  = new StartingDriver;
        $this->verifying = new VerifyingDriver;
        $this->person    = new IdentityReference('App\Models\User', '7');

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance('request', Request::create('/auth/sso', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.domain_linking', true);
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $driver = self::driver($this->starting, $this->verifying);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): ProtocolDriver => $driver);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::migration(self::SINGLE_USE_MIGRATION)->up(); // @phpstan-ignore method.notFound
        self::migration(self::RATE_LIMITS_MIGRATION)->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection([
            'protocol'                => VerifyingDriver::NAME,
            'enabled'                 => true,
            'settings'                => ['issuer' => VerifyingDriver::ISSUER],
            'attribute_mapping'       => ['email' => 'mail'],
            'linking_enabled'         => true,
            'linking_issuer_class'    => 'single_organization',
            'linking_acknowledged_at' => CarbonImmutable::parse('2026-11-01T00:00:00Z'),
        ]);

        $now          = CarbonImmutable::parse('2026-11-01T09:30:00Z');
        $this->domain = $this->makeDomain($this->connection, 'example.com', [
            'state'                    => DomainState::VERIFIED,
            'verified_domain'          => 'example.com',
            'verified_at'              => $now->subDay(),
            'verification_generation'  => 1,
            'last_successful_check_at' => $now,
        ]);

        $this->matcher    = new ScriptedEmailMatcher(LinkEmailMatch::exactlyOne($this->person));
        $this->scope      = new ScriptedPrincipalScope;
        $this->membership = new ScriptedTenantMembership(MembershipStanding::accepted($now->subDays(2)));

        $this->confirmation = new ScriptedLinkConfirmation;

        $this->app?->instance(Linker::class, app(LinkStore::class));
        $this->app?->instance(LinkEmailMatcher::class, $this->matcher);
        $this->app?->instance(PrincipalScope::class, $this->scope);
        $this->app?->instance(TenantMembership::class, $this->membership);
        $this->app?->instance(LinkConfirmation::class, $this->confirmation);

        $this->verifying->claims = $this->claims();

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
        self::migration(self::RATE_LIMITS_MIGRATION)->down(); // @phpstan-ignore method.notFound
        self::migration(self::SINGLE_USE_MIGRATION)->down(); // @phpstan-ignore method.notFound
        $this->dropDomainsTable();
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * What the driver verifies: a subject with the linking email, from the ID
     * token.
     *
     * @param  ?string  $email
     * @param  ?string  $organization
     * @return \SineMacula\Laravel\Sso\Results\VerifiedClaims
     */
    protected function claims(?string $email = self::EMAIL, ?string $organization = null): VerifiedClaims
    {
        return new VerifiedClaims(
            VerifyingDriver::ISSUER,
            VerifyingDriver::SUBJECT,
            null,
            ['mail' => (string) $email],
            new AuthenticationContext($this->clock->now()),
            $email === null ? null : new LinkingEmail($email, LinkingEmailSource::ID_TOKEN, $organization),
        );
    }

    /**
     * Start a flow for the purpose.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $session
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    protected function start(Purpose $purpose = Purpose::SIGN_IN, ?IdentityReference $identity = null, ?string $session = null): StartResult
    {
        $start = app(AuthorizationRequestService::class)->start('web', $purpose, $this->connection->id, null, $identity, $session);

        static::assertTrue($start->isStarted());

        return $start;
    }

    /**
     * Answer the last flow started at its callback.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \LogicException
     */
    protected function complete(): CompletionResult
    {
        $state = $this->starting->lastStart()->state->reveal();

        return app(CompletionService::class)->callback($this->connection->id, new CompletionRequest('GET', 'state=' . rawurlencode($state), []));
    }

    /**
     * Redeem the completion's code with the start's verifier, inside the
     * caller's transaction, as a session-admitting redeemer does.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    protected function admit(CompletionResult $completion, StartResult $start, Purpose $purpose = Purpose::SIGN_IN, ?IdentityReference $caller = null): RedemptionResult
    {
        $code     = (string) $completion->handoff?->code->reveal();
        $verifier = (string) $start->verifier?->reveal();

        return $this->connection->getConnection()->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit($purpose, 'web', $this->connection->id, $code, $verifier, $caller),
        );
    }

    /**
     * A shipped migration.
     *
     * @param  string  $file
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function migration(string $file): Migration
    {
        return require dirname(__DIR__, 3) . $file;
    }

    /**
     * A driver that starts as the starting driver and completes as the
     * verifying one.
     *
     * @param  \Tests\Fixtures\Protocols\StartingDriver  $starting
     * @param  \Tests\Fixtures\Protocols\VerifyingDriver  $verifying
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolDriver
     */
    private static function driver(StartingDriver $starting, VerifyingDriver $verifying): ProtocolDriver
    {
        return new readonly class ($starting, $verifying) implements ProtocolDriver {
            /**
             * Constructor.
             *
             * @param  \Tests\Fixtures\Protocols\StartingDriver  $starting
             * @param  \Tests\Fixtures\Protocols\VerifyingDriver  $verifying
             */
            public function __construct(

                /** Starts each flow, recording its state. */
                private StartingDriver $starting,

                /** Correlates and validates each response. */
                private VerifyingDriver $verifying,
            ) {}

            /**
             * The verifying driver's settings.
             *
             * @param  array<array-key, mixed>  $values
             * @return \SineMacula\Laravel\Sso\Contracts\ProtocolSettings
             */
            #[\Override]
            public function settings(array $values): ProtocolSettings
            {
                return $this->verifying->settings($values);
            }

            /**
             * Whether the verifying driver counts the connection complete.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return bool
             */
            #[\Override]
            public function isComplete(SsoConnection $connection): bool
            {
                return $this->verifying->isComplete($connection);
            }

            /**
             * Start as the starting driver.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
             * @return \SineMacula\Laravel\Sso\Protocols\Start
             */
            #[\Override]
            public function start(SsoConnection $connection, StartRequest $request): Start
            {
                return $this->starting->start($connection, $request);
            }

            /**
             * Correlate as the verifying driver.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
             * @return \SineMacula\Laravel\Sso\Protocols\Correlation
             */
            #[\Override]
            public function correlate(SsoConnection $connection, CompletionRequest $request): Correlation
            {
                return $this->verifying->correlate($connection, $request);
            }

            /**
             * Validate as the verifying driver.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
             * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
             * @return \SineMacula\Laravel\Sso\Protocols\Completion
             */
            #[\Override]
            public function complete(SsoConnection $connection, CompletionRequest $request, ConsumedRequest $consumed): Completion
            {
                return $this->verifying->complete($connection, $request, $consumed);
            }

            /**
             * Describe as the verifying driver.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
             */
            #[\Override]
            public function describe(SsoConnection $connection): ServiceProviderDescription
            {
                return $this->verifying->describe($connection);
            }
        };
    }
}
