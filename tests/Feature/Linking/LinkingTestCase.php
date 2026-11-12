<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
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
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
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
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Linking\ScriptedEmailMatcher;
use Tests\Fixtures\Linking\ScriptedLinkConfirmation;
use Tests\Fixtures\Linking\ScriptedPrincipalScope;
use Tests\Fixtures\Linking\ScriptedTenantMembership;
use Tests\Fixtures\Protocols\StartingDriver;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Base case for the linking state machine: every condition holds, and a test
 * withdraws one.
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

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.domain_linking', true);
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $driver = self::driver($this->starting, $this->verifying);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): ProtocolDriver => $driver);

        $this->usePackageTables();

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
     * Start a flow for the purpose, for the identity on the session as its
     * caller, when an identity is given.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $session
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    protected function start(Purpose $purpose = Purpose::SIGN_IN, ?IdentityReference $identity = null, ?string $session = null): StartResult
    {
        $start = app(AuthorizationRequestService::class)->start(
            'web',
            $purpose,
            $this->connection->id,
            Clients::browser(),
            null,
            $identity === null ? null : new Caller($identity, $session),
        );

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

        return app(CompletionService::class)->complete(
            CompletionEndpoint::CALLBACK,
            $this->connection->id,
            new CompletionRequest('GET', 'state=' . rawurlencode($state), []),
            Clients::browser(),
        );
    }

    /**
     * Redeem the code inside the caller's transaction; an identity alone is a
     * caller with no session.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Identities\Caller|\SineMacula\Laravel\Sso\Identities\IdentityReference|null  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    protected function admit(CompletionResult $completion, StartResult $start, Purpose $purpose = Purpose::SIGN_IN, Caller|IdentityReference|null $caller = null): RedemptionResult
    {
        $code     = (string) $completion->handoff?->code->reveal();
        $verifier = (string) $start->verifier?->reveal();

        return $this->connection->getConnection()->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit(
                $purpose,
                'web',
                $this->connection->id,
                $code,
                $verifier,
                Clients::browser(),
                $caller instanceof IdentityReference ? new Caller($caller) : $caller,
            ),
        );
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
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Protocols\Completion
             */
            #[\Override]
            public function complete(SsoConnection $connection, CompletionRequest $request, ConsumedRequest $consumed, ClientContext $client): Completion
            {
                return $this->verifying->complete($connection, $request, $consumed, $client);
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
