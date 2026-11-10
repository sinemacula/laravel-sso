<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\TestCase;

/**
 * The events a SAML completion reports (SSO-10.1, SSO-10.2, SSO-6.6, SSO-9.8):
 * `ResultVerified` then `HandoffIssued` for a sign-in; one `FlowFailed` alone
 * for a response refused before it was verified; `ResultVerified` then one
 * `FlowFailed` with `replayed` for an assertion recorded before; each naming
 * the request only by its public reference; and no event, event dump or log
 * ever carrying the assertion, the `SAMLResponse`, the `RelayState`, the
 * `NameID` or an attribute's value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(AssertionValidator::class)]
final class SamlCompletionEventSequenceTest extends TestCase
{
    use CapturesLogs, DumpsValues, RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The `AuthnRequest` id the request was started with. */
    private const string REQUEST_ID = '_request-reported-1';

    /** @var string The `RelayState` the request was started with. */
    private const string RELAY_STATE = 'relay-state-value-of-the-reported-request';

    /** @var string The subject's `NameID`, never reported. */
    private const string NAME_ID = 'name-id-value-never-reported-4f1c';

    /** @var string An attribute's value, never reported. */
    private const string ATTRIBUTE = 'attribute-value-never-reported@example.test';

    /** @var string The assertion's id. */
    private const string ASSERTION_ID = '_assertion-id-never-reported-77b2';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The SAML connection signed in through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\AuthorizationRequest The request the response answers. */
    private AuthorizationRequest $request;

    /**
     * Bind a fixed clock, the recording issuer and a request from an IP
     * address, configure SAML, the endpoints and the application, create the
     * tables, a connection that trusts the identity provider and its request,
     * capture logs and record events.
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
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'tenant_id'         => 'tenant-reported',
            'protocol'          => 'saml2',
            'enabled'           => true,
            'settings'          => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
            'attribute_mapping' => ['email' => 'mail'],
        ]);

        $this->trust(self::idp()->certificate());

        $this->request = $this->makeAuthorizationRequest($this->connection, ['saml_request_id' => self::REQUEST_ID, 'state_digest' => hash('sha256', self::RELAY_STATE)]);

        $this->captureLogs();
        $this->startRecordingEvents();
    }

    /**
     * A sign-in reports `ResultVerified` then `HandoffIssued`, each for the
     * connection, its tenant and protocol, the application, the purpose and the
     * request's public reference, and no failure.
     *
     * @return void
     */
    public function testASignInReportsResultVerifiedThenHandoffIssued(): void
    {
        self::assertTrue($this->complete($this->response())->isCompleted());

        $this->assertEventSequence([ResultVerified::class, ResultUnlinked::class, HandoffIssued::class]);
        $this->assertNoFailure();

        $expected = [$this->connection->id, 'tenant-reported', 'saml2', 'web', 'sign_in', $this->request->reference];

        foreach ($this->recordedEvents() as $event) {
            $context = $event->context();

            self::assertSame(
                $expected,
                [$context->connectionId, $context->connectionTenantId, $context->protocol, $context->application, $context->purpose, $context->requestReference],
            );
        }
    }

    /**
     * A response refused before it was verified reports exactly one
     * `FlowFailed`, with nothing before it.
     *
     * @return void
     */
    public function testARefusalBeforeVerificationReportsOneFailureAlone(): void
    {
        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->complete($this->response()->signed(false, false))->reason);

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::ASSERTION, FailureReason::SIGNATURE_INVALID);
    }

    /**
     * An assertion recorded before is verified, then refused when its record is
     * made: `ResultVerified`, then one `FlowFailed` with `replayed`, and no
     * code.
     *
     * @return void
     */
    public function testAReplayedAssertionReportsResultVerifiedThenReplayed(): void
    {
        $until = $this->clock->now()->addMinutes(6);

        $record = ReplayRecord::samlAssertion($this->connection->id, FakeSamlIdentityProvider::ENTITY_ID, self::ASSERTION_ID, $until);

        app(SingleUseStore::class)->record($record->namespace, $record->key(), $record->until);

        $result = $this->complete($this->response());

        self::assertSame([true, FailureReason::REPLAYED], [$result->isFailed(), $result->reason]);
        $this->assertEventSequence([ResultVerified::class, FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::ASSERTION, FailureReason::REPLAYED);
    }

    /**
     * Across a sign-in, a replay, a refused read and an unsuccessful status, no
     * event, no dump or encoding of one, and no log carries the assertion or
     * its id, the posted `SAMLResponse`, the `RelayState`, the `NameID` or an
     * attribute's value.
     *
     * @return void
     */
    public function testNoEventOrLogCarriesWhatTheResponseCarried(): void
    {
        $responses = [
            $this->response(),
            $this->response()->with(['response_id' => '_response-replayed']),
            $this->response()->signed(false, false),
            $this->response()->with(['status' => 'urn:oasis:names:tc:SAML:2.0:status:Responder', 'status_message' => 'Denied by policy', 'assertion' => false]),
        ];

        $posted = [];

        foreach ($responses as $index => $response) {

            $requestId = $index === 0 ? self::REQUEST_ID : self::REQUEST_ID . '-' . $index;
            $relay     = $index === 0 ? self::RELAY_STATE : self::RELAY_STATE . '-' . $index;

            if ($index > 0) {
                $this->makeAuthorizationRequest($this->connection, ['saml_request_id' => $requestId, 'state_digest' => hash('sha256', $relay)]);
            }

            $request = $response->inResponseTo($requestId)->completionRequest($relay);
            $saml    = $request->body()['SAMLResponse'];

            self::assertIsString($saml);

            $posted[] = $saml;
            $posted[] = $relay;

            app(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connection->id, $request, Clients::browser());
        }

        self::assertNotSame([], $this->capturedLogRecords());
        self::assertSame(
            [ResultVerified::class, ResultUnlinked::class, HandoffIssued::class, ResultVerified::class, FlowFailed::class, FlowFailed::class, FlowFailed::class],
            array_map(static fn (SsoEvent $event): string => $event::class, $this->recordedEvents()),
        );

        $secrets = [...$posted, self::NAME_ID, self::ATTRIBUTE, self::ASSERTION_ID, '<saml:Assertion', 'name-id-value'];

        $this->assertNothingLoggedContains(...$secrets);
        $this->assertNothingReportedContains($secrets);
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
        // The unlinked-result event alone carries the result (SSO-8.6), to its
        // synchronous listeners
        $events = array_values(array_filter($this->recordedEvents(), static fn (SsoEvent $event): bool => !$event instanceof ResultUnlinked));
        $texts  = [...array_values(self::dumps($events)), (string) json_encode($events, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR)];

        foreach ($needles as $needle) {
            foreach ($texts as $text) {
                self::assertStringNotContainsString($needle, $text);
            }
        }
    }

    /**
     * Complete at the connection's assertion consumer service with the
     * response, posted with the request's `RelayState`.
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
     * A valid response from the trusted identity provider, made now, answering
     * the request, with the subject, attribute and assertion id never to be
     * reported.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function response(): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->clock->now())
            ->with(['name_id' => self::NAME_ID, 'assertion_id' => self::ASSERTION_ID, 'attributes' => ['mail' => [self::ATTRIBUTE]]])
            ->inResponseTo(self::REQUEST_ID);
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
