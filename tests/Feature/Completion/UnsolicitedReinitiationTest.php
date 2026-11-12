<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\UnsolicitedReinitiation;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\UnsolicitedResponseReinitiated;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\TestCase;

/**
 * Feature tests for the client an unsolicited SAML response re-initiates for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnsolicitedReinitiation::class)]
final class UnsolicitedReinitiationTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The `RelayState` the identity provider posts. */
    private const string RELAY_STATE = 'https://relay-state.example.test/9c2e';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The SAML connection the responses arrive for. */
    private Connection $connection;

    /**
     * Configure IdP-initiated SAML and a request never read; record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(HandoffIssuer::class, new RecordingHandoffIssuer);
        $this->app?->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => 'Served/1.0']));

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.idp_initiated', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'protocol' => 'saml2',
            'enabled'  => true,
            'settings' => [
                'idp_entity_id'           => FakeSamlIdentityProvider::ENTITY_ID,
                'sso_url'                 => FakeSamlIdentityProvider::SSO_URL,
                'idp_initiated'           => true,
                'idp_initiated_start_url' => 'https://app.example.com/sso/start',
            ],
            'attribute_mapping' => ['email' => 'mail'],
        ]);

        $this->trust(self::idp()->certificate());

        $this->startRecordingEvents();
    }

    /**
     * A re-initiation is reported with the client the completion was given.
     *
     * @return void
     */
    public function testAReinitiationIsReportedWithTheClient(): void
    {
        self::assertTrue($this->complete($this->response(), new ClientContext('203.0.113.7', 'Example/1.0'))->isReinitiated());

        $this->assertEventSequence([UnsolicitedResponseReinitiated::class]);

        $context = $this->recordedEvents()[0]->context();

        self::assertSame(['203.0.113.7', 'Example/1.0'], [$context->ip, $context->userAgent]);
        self::assertSame($this->connection->id, $context->connectionId);
    }

    /**
     * A replay refused under the lock reports the replaying client.
     *
     * @return void
     */
    public function testAReplayRefusedUnderTheLockIsReportedWithItsClient(): void
    {
        $response = $this->response();

        self::assertTrue($this->complete($response, new ClientContext('203.0.113.7', 'Example/1.0'))->isReinitiated());

        $this->startRecordingEvents();

        self::assertSame(FailureReason::REPLAYED, $this->complete($response, new ClientContext('192.0.2.44', 'Replayer/1.0'))->reason);

        $this->assertEventSequence([FlowFailed::class]);

        $context = $this->assertExactlyOneFailure(Flow::ASSERTION, FailureReason::REPLAYED)->context();

        self::assertSame(['192.0.2.44', 'Replayer/1.0'], [$context->ip, $context->userAgent]);
    }

    /**
     * A re-initiation for no client reports no address or user agent.
     *
     * @return void
     */
    public function testAReinitiationForNoClientReportsNone(): void
    {
        self::assertTrue($this->complete($this->response(), new ClientContext(null, null))->isReinitiated());

        $context = $this->recordedEvents()[0]->context();

        self::assertSame([null, null], [$context->ip, $context->userAgent]);
    }

    /**
     * Complete at the assertion consumer service for the client.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(FakeSamlResponse $response, ClientContext $client): CompletionResult
    {
        $request = $response->completionRequest(self::RELAY_STATE);

        return app(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connection->id, $request, $client);
    }

    /**
     * A valid unsolicited response from the trusted identity provider.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function response(): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->clock->now());
    }

    /**
     * Trust the identity provider's signing certificate on the connection.
     *
     * @param  string  $certificate
     * @return void
     *
     * @throws \LogicException
     */
    private function trust(string $certificate): void
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A certificate has a public key.'));

        (new ConnectionKey)->forceFill([
            'connection_id' => $this->connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $certificate,
            'public_key'    => is_array($details) ? $details['key'] : '',
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();
    }

    /**
     * The trusted identity provider, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
