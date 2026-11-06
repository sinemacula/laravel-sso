<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionEvents;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\UnsolicitedReinitiation;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\UnsolicitedResponseReinitiated;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Saml2\UnsolicitedResponses;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\TestCase;

/**
 * The events an unsolicited SAML response reports (SSO-5.8, SSO-10.1,
 * SSO-10.2, SSO-10.4): `UnsolicitedResponseReinitiated` alone for a
 * re-initiation; exactly one `FlowFailed` for the assertion flow alone for a
 * refusal, before or under the connection's lock; each naming the connection,
 * its tenant and its protocol, and never a request, an application, a purpose
 * or an identity; and no event, event dump or log ever carrying the
 * assertion, the `SAMLResponse`, the `RelayState`, the `NameID` or an
 * attribute's value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionEvents::class)]
#[CoversClass(UnsolicitedReinitiation::class)]
#[CoversClass(UnsolicitedResponses::class)]
final class SamlReinitiationEventSequenceTest extends TestCase
{
    use CapturesLogs, DumpsValues, RecordsEventSequences, UsesConnections;

    /** @var string The `RelayState` the identity provider posts, never reported. */
    private const string RELAY_STATE = 'https://relay-state-never-reported.example.test/9c2e';

    /** @var string The subject's `NameID`, never reported. */
    private const string NAME_ID = 'name-id-value-never-reported-5d3a';

    /** @var string An attribute's value, never reported. */
    private const string ATTRIBUTE = 'attribute-value-never-reported@example.test';

    /** @var string The assertion's id, never reported. */
    private const string ASSERTION_ID = '_assertion-id-never-reported-81c4';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The SAML connection the responses arrive for. */
    private Connection $connection;

    /**
     * Bind a fixed clock, the recording issuer and a request from an IP
     * address, configure SAML, IdP-initiated sign-in, the endpoints and the
     * application, create the tables and a connection that allows IdP-initiated
     * sign-in and trusts the identity provider, capture logs and record events.
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
        $this->app?->instance('request', Request::create('/auth/sso/connections/x/assertions', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.idp_initiated', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'tenant_id' => 'tenant-reinitiated',
            'protocol'  => 'saml2',
            'enabled'   => true,
            'settings'  => [
                'idp_entity_id'           => FakeSamlIdentityProvider::ENTITY_ID,
                'sso_url'                 => FakeSamlIdentityProvider::SSO_URL,
                'idp_initiated'           => true,
                'idp_initiated_start_url' => 'https://app.example.com/sso/start',
            ],
            'attribute_mapping' => ['email' => 'mail'],
        ]);

        $this->trust(self::idp()->certificate());

        $this->captureLogs();
        $this->startRecordingEvents();
    }

    /**
     * A re-initiation reports `UnsolicitedResponseReinitiated` alone, its
     * context the connection, its tenant and protocol and the client, and
     * nothing of a request, an application or an identity.
     *
     * @return void
     */
    public function testAReinitiationReportsUnsolicitedResponseReinitiatedAlone(): void
    {
        self::assertTrue($this->complete($this->response())->isReinitiated());

        $this->assertEventSequence([UnsolicitedResponseReinitiated::class]);
        $this->assertNoFailure();
        $this->assertContextNamesTheConnectionOnly($this->recordedEvents()[0]->context());
    }

    /**
     * A response refused before the lock reports exactly one `FlowFailed` for
     * the assertion flow, with nothing before it, naming the connection only.
     *
     * @return void
     */
    public function testARefusalBeforeTheLockReportsOneFailureAlone(): void
    {
        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->complete($this->response()->signed(false, false))->reason);

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertContextNamesTheConnectionOnly($this->assertExactlyOneFailure(Flow::ASSERTION, FailureReason::SIGNATURE_INVALID)->context());
    }

    /**
     * A connection that does not allow IdP-initiated sign-in reports exactly
     * one `FlowFailed` with `unsolicited_not_allowed`.
     *
     * @return void
     */
    public function testANotAllowedResponseReportsOneFailureAlone(): void
    {
        $this->connection->forceFill(['settings' => [...$this->connection->settings, 'idp_initiated' => false]])->save();

        self::assertSame(FailureReason::UNSOLICITED_NOT_ALLOWED, $this->complete($this->response())->reason);

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertContextNamesTheConnectionOnly($this->assertExactlyOneFailure(Flow::ASSERTION, FailureReason::UNSOLICITED_NOT_ALLOWED)->context());
    }

    /**
     * A second post of the same response, refused under the lock with
     * `replayed`, reports exactly one `FlowFailed` after the first post's
     * `UnsolicitedResponseReinitiated`, and no second re-initiation.
     *
     * @return void
     */
    public function testAReplayUnderTheLockReportsOneFailure(): void
    {
        $response = $this->response();

        self::assertTrue($this->complete($response)->isReinitiated());
        self::assertSame(FailureReason::REPLAYED, $this->complete($response)->reason);

        $this->assertEventSequence([UnsolicitedResponseReinitiated::class, FlowFailed::class]);
        $this->assertContextNamesTheConnectionOnly($this->assertExactlyOneFailure(Flow::ASSERTION, FailureReason::REPLAYED)->context());
    }

    /**
     * Across a re-initiation, a replay, a refused read, an unsuccessful status
     * and a connection that does not allow it, no event, no dump or encoding of
     * one, and no log carries the assertion or its id, the posted
     * `SAMLResponse`, the `RelayState`, the `NameID` or an attribute's value.
     *
     * @return void
     */
    public function testNoEventOrLogCarriesWhatTheResponseCarried(): void
    {
        $responses = [
            $this->response(),
            $this->response(),
            $this->response()->signed(false, false),
            $this->response()->with(['status' => 'urn:oasis:names:tc:SAML:2.0:status:Responder', 'status_message' => 'Denied by policy', 'assertion' => false]),
        ];

        $posted = [];

        foreach ($responses as $response) {

            $request = $response->completionRequest(self::RELAY_STATE);
            $encoded = $request->body()['SAMLResponse'] ?? null;

            self::assertIsString($encoded);

            $posted[] = $encoded;

            app(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connection->id, $request, Clients::browser());
        }

        $this->connection->forceFill(['settings' => [...$this->connection->settings, 'idp_initiated' => false]])->save();

        $this->complete($this->response());

        self::assertNotSame([], $this->capturedLogRecords());
        self::assertSame(
            [UnsolicitedResponseReinitiated::class, FlowFailed::class, FlowFailed::class, FlowFailed::class, FlowFailed::class],
            array_map(static fn (SsoEvent $event): string => $event::class, $this->recordedEvents()),
        );

        $secrets = [...$posted, self::RELAY_STATE, 'relay-state-never-reported', self::NAME_ID, self::ATTRIBUTE, self::ASSERTION_ID, '<saml:Assertion', 'name-id-value'];

        $this->assertNothingLoggedContains(...$secrets);
        $this->assertNothingReportedContains($secrets);
    }

    /**
     * Assert the context names the connection, its tenant and its protocol, and
     * the client, and no request, application, purpose, identity or session.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @return void
     */
    private function assertContextNamesTheConnectionOnly(EventContext $context): void
    {
        self::assertSame(
            [$this->connection->id, 'tenant-reinitiated', 'saml2', '203.0.113.7', '2026-11-01T09:30:00+00:00'],
            [$context->connectionId, $context->connectionTenantId, $context->protocol, $context->ip, $context->occurredAt->toIso8601String()],
        );
        self::assertSame(
            [null, null, null, null, null, null],
            [$context->application, $context->purpose, $context->requestReference, $context->identityMorphClass, $context->identityId, $context->sessionId],
        );
    }

    /**
     * Assert no recorded event, as dumped any way or encoded as JSON, contains
     * any of the needles.
     *
     * @param  list<string>  $needles
     * @return void
     */
    private function assertNothingReportedContains(array $needles): void
    {
        $events = $this->recordedEvents();
        $texts  = [...array_values(self::dumps($events)), (string) json_encode($events, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR)];

        foreach ($needles as $needle) {
            foreach ($texts as $text) {
                self::assertStringNotContainsString($needle, $text);
            }
        }
    }

    /**
     * Complete at the connection's assertion consumer service with the
     * response, posted with the identity provider's `RelayState`.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(FakeSamlResponse $response): CompletionResult
    {
        return app(CompletionService::class)->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $this->connection->id,
            $response->completionRequest(self::RELAY_STATE),
            Clients::browser(),
        );
    }

    /**
     * A valid unsolicited response from the trusted identity provider, made
     * now, with the subject, attribute and assertion id never to be reported.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function response(): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->clock->now())
            ->with(['name_id' => self::NAME_ID, 'assertion_id' => self::ASSERTION_ID, 'attributes' => ['mail' => [self::ATTRIBUTE]]]);
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
