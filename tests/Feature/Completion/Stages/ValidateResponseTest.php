<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion\Stages;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Feature tests for the validation stage of a completion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ValidateResponse::class)]
final class ValidateResponseTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The name the recording driver is registered under. */
    private const string DRIVER = 'recording';

    /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Http\ClientContext> Each client the driver was given. */
    private \ArrayObject $clients;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection over the recording driver. */
    private Connection $connection;

    /**
     * Register a driver that records clients, and create a connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clients = new \ArrayObject;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        config()->set('sso.features.oidc', true);

        $driver = self::recordingDriver(new VerifyingDriver, $this->clients);

        app(ProtocolManager::class)->extend(self::DRIVER, fn (): ProtocolDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'protocol'          => self::DRIVER,
            'enabled'           => true,
            'settings'          => ['issuer' => VerifyingDriver::ISSUER],
            'attribute_mapping' => ['email' => 'mail'],
        ]);
    }

    /**
     * The driver is given the state's client.
     *
     * @return void
     */
    public function testTheDriverIsGivenTheStatesClient(): void
    {
        $client   = new ClientContext('203.0.113.7', 'Example/1.0');
        $consumed = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString('Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456'), CarbonImmutable::parse('2026-11-01T09:29:00Z'));
        $state    = CompletionState::arrived($this->connection->id, new CompletionRequest('GET', 'state=staged', []), $client)
            ->withConnection($this->connection)
            ->withCorrelation(Correlation::solicited('staged'))
            ->withAuthorizationRequest(null, $consumed, null);

        $outcome = app(ValidateResponse::class)->run($state);

        self::assertTrue($outcome->isProceeding());
        self::assertSame(VerifyingDriver::SUBJECT, $outcome->state->result?->subject);
        self::assertSame([$client], $this->clients->getArrayCopy());
        self::assertSame($client, $outcome->state->client);
    }

    /**
     * A verifying driver that records each client `complete()` is given.
     *
     * @param  \Tests\Fixtures\Protocols\VerifyingDriver  $verifying
     * @param  \ArrayObject<int, \SineMacula\Laravel\Sso\Http\ClientContext>  $clients
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolDriver
     */
    private static function recordingDriver(VerifyingDriver $verifying, \ArrayObject $clients): ProtocolDriver
    {
        return new readonly class ($verifying, $clients) implements ProtocolDriver {
            /**
             * Constructor.
             *
             * @param  \Tests\Fixtures\Protocols\VerifyingDriver  $verifying
             * @param  \ArrayObject<int, \SineMacula\Laravel\Sso\Http\ClientContext>  $clients
             */
            public function __construct(

                /** The driver every call is handed to. */
                private VerifyingDriver $verifying,

                /** Each client `complete()` was given. */
                private \ArrayObject $clients,
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
             * Whether the verifying driver finds the connection complete.
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
             * Start as the verifying driver does.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
             * @return \SineMacula\Laravel\Sso\Protocols\Start
             */
            #[\Override]
            public function start(SsoConnection $connection, StartRequest $request): Start
            {
                return $this->verifying->start($connection, $request);
            }

            /**
             * Correlate as the verifying driver does.
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
             * Record the client, then complete as the verifying driver does.
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
                $this->clients->append($client);

                return $this->verifying->complete($connection, $request, $consumed, $client);
            }

            /**
             * Describe as the verifying driver does.
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
