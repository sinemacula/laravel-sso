<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\ResponseCorrelator;
use SineMacula\Laravel\Sso\Protocols\Saml2\ResponseValidator;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\TestCase;

/**
 * Feature tests for completing a SAML sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(ResponseCorrelator::class)]
#[CoversClass(ResponseValidator::class)]
#[CoversClass(AssertionValidator::class)]
final class SamlCompletionTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The `AuthnRequest` id the request was started with. */
    private const string REQUEST_ID = '_request-completed-1';

    /** @var string The `RelayState` the request was started with. */
    private const string RELAY_STATE = 'the-relay-state-of-the-completed-saml-request';

    /** @var string The `web` application's redirect URI. */
    private const string REDIRECT_URI = 'https://app.example.com/sso';

    /** @var string AES-128-CBC. */
    private const string AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';

    /** @var string The basic attribute name format. */
    private const string BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?array{0: string, 1: string} The service provider's encryption key and certificate, made once. */
    private static ?array $spKeys = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Handoffs\RecordingHandoffIssuer The handoff issuer. */
    private RecordingHandoffIssuer $issuer;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The SAML connection signed in through. */
    private Connection $connection;

    /**
     * Configure SAML and create a connection that trusts the identity provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock  = new FixedClock('2026-11-01T09:30:00Z');
        $this->issuer = new RecordingHandoffIssuer;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(HandoffIssuer::class, $this->issuer);
        $this->app?->instance('request', Request::create('/auth/sso/connections/x/assertions', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.encrypted_assertions', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => self::REDIRECT_URI, 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'tenant_id'         => 'tenant-saml',
            'protocol'          => 'saml2',
            'enabled'           => true,
            'settings'          => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
            'attribute_mapping' => ['email' => 'email'],
        ]);

        $this->key(KeyUse::IDP_SIGNING, null, self::idp()->certificate(), null);
    }

    /**
     * A response with a signed assertion completes.
     *
     * @return void
     */
    public function testASignedAssertionCompletes(): void
    {
        $request = $this->request();
        $result  = $this->complete($this->response()->with(['assertion_id' => '_assertion-signed']));

        self::assertTrue($result->isCompleted());
        self::assertSame([self::REDIRECT_URI, $request->reference], [$result->redirectUri, $result->reference?->value]);
        $this->assertSignedIn('v1|7:name_id|52:' . FakeSamlResponse::PERSISTENT . '|-|-|5:alice', FakeSamlResponse::PERSISTENT);
        $this->assertRecorded('_assertion-signed', '2026-11-01T09:36:00+00:00');

        $row = AuthorizationRequest::query()->whereKey($request->id)->sole();

        self::assertSame(['2026-11-01T09:30:00+00:00', '2026-11-01T09:30:00+00:00'], [$row->consumed_at?->toIso8601String(), $row->completed_at?->toIso8601String()]);
    }

    /**
     * A response signed only in its envelope completes when allowed.
     *
     * @return void
     */
    public function testASignedResponseCompletes(): void
    {
        $this->settings(['want_assertions_signed' => false]);
        $this->request();

        $result = $this->complete($this->response()->signed(true, false)->with(['assertion_id' => '_assertion-response', 'not_on_or_after' => $this->clock->now()->addMinutes(2)]));

        self::assertTrue($result->isCompleted());
        $this->assertSignedIn('v1|7:name_id|52:' . FakeSamlResponse::PERSISTENT . '|-|-|5:alice', FakeSamlResponse::PERSISTENT);
        $this->assertRecorded('_assertion-response', '2026-11-01T09:33:00+00:00');
    }

    /**
     * An assertion encrypted with RSA-OAEP and AES-128-GCM completes.
     *
     * @return void
     */
    public function testAnEncryptedAssertionCompletes(): void
    {
        $this->settings(['require_encrypted_assertions' => true]);
        $this->key(KeyUse::SP_ENCRYPTION, KeyState::CURRENT, self::spKeys()[1], self::spKeys()[0]);
        $this->request();

        $result = $this->complete($this->response()->with(['assertion_id' => '_assertion-gcm'])->encryptedFor(self::spKeys()[1]));

        self::assertTrue($result->isCompleted());
        $this->assertSignedIn('v1|7:name_id|52:' . FakeSamlResponse::PERSISTENT . '|-|-|5:alice', FakeSamlResponse::PERSISTENT);
        $this->assertRecorded('_assertion-gcm', '2026-11-01T09:36:00+00:00');
    }

    /**
     * An assertion encrypted with AES-128-CBC completes once listed.
     *
     * @return void
     */
    public function testAnAssertionEncryptedWithAesCbcCompletesByOptIn(): void
    {
        $this->settings(['encryption_algorithms' => ['http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', self::AES128_CBC]]);
        $this->key(KeyUse::SP_ENCRYPTION, KeyState::CURRENT, self::spKeys()[1], self::spKeys()[0]);
        $this->request();

        $response = $this->response()->with(['assertion_id' => '_assertion-cbc'])->signed(true, true)->encryptedFor(self::spKeys()[1], 'rsa-oaep-mgf1p', 'aes128-cbc');

        self::assertTrue($this->complete($response)->isCompleted());
        $this->assertRecorded('_assertion-cbc', '2026-11-01T09:36:00+00:00');
    }

    /**
     * A subject taken from an attribute completes with no `NameID` format.
     *
     * @return void
     */
    public function testAnAttributeSubjectCompletes(): void
    {
        $this->settings(['subject_source' => 'attribute', 'subject_attribute' => 'employeeNumber']);
        $this->request();

        $response = $this->response()->with([
            'name_id_format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            'attributes'     => ['employeeNumber' => ['E-1001'], 'email' => ['alice@example.test']],
        ]);

        self::assertTrue($this->complete($response)->isCompleted());
        $this->assertSignedIn('v1|9:attribute|14:employeeNumber|49:' . self::BASIC . '|6:E-1001', null);
    }

    /**
     * A second post of the same response finds its request consumed.
     *
     * @return void
     */
    public function testASecondPostOfTheSameResponseFindsItsRequestConsumed(): void
    {
        $this->request();

        $response = $this->response()->with(['assertion_id' => '_assertion-twice']);

        self::assertTrue($this->complete($response)->isCompleted());

        $second = $this->complete($response);

        self::assertSame([true, FailureReason::REQUEST_UNKNOWN], [$second->isRejected(), $second->reason]);
        self::assertCount(1, $this->issuer->grants());
        $this->assertRecorded('_assertion-twice', '2026-11-01T09:36:00+00:00');
    }

    /**
     * Expired metadata refuses the completion with `metadata_expired`.
     *
     * @return void
     */
    public function testExpiredMetadataRefusesTheCompletion(): void
    {
        $this->optInToRefresh();
        $this->connection->forceFill(['metadata_fetched_at' => $this->clock->now()->subHours(2), 'metadata_valid_until' => $this->clock->now()->subHour()])->save();
        $this->request();

        $result = $this->complete($this->response());

        self::assertSame([true, FailureReason::METADATA_EXPIRED], [$result->isFailed(), $result->reason]);
        self::assertSame([], $this->issuer->grants());
        self::assertSame(0, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
    }

    /**
     * Rows of `[seconds, reason]` for metadata valid a minute after validation.
     *
     * @return iterable<string, array{0: int, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideMetadataLapses(): iterable
    {
        yield 'a second before' => [59, null];
        yield 'at the instant' => [60, FailureReason::METADATA_EXPIRED];
        yield 'a second after' => [61, FailureReason::METADATA_EXPIRED];
    }

    /**
     * Metadata that lapses after validation is refused under the lock.
     *
     * @param  int  $seconds
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideMetadataLapses')]
    public function testMetadataThatLapsedAfterValidationIsRefusedUnderTheLock(int $seconds, ?FailureReason $reason): void
    {
        $clock = $this->clock;

        $this->optInToRefresh();
        $this->connection->forceFill(['metadata_fetched_at' => $clock->now()->subHour(), 'metadata_valid_until' => $clock->now()->addMinute()])->save();
        $this->request();

        app()->bind(ValidateResponse::class, static function ($app) use ($clock, $seconds): CompletionStage {

            $stage = $app->build(ValidateResponse::class);

            return new readonly class ($stage, $clock, $seconds) implements CompletionStage {
                /**
                 * Constructor.
                 *
                 * @param  \SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse  $stage
                 * @param  \Tests\Fixtures\FixedClock  $clock
                 * @param  int  $seconds
                 */
                public function __construct(

                    /** The real validation. */
                    private ValidateResponse $stage,

                    /** The clock moved on once the response is validated. */
                    private FixedClock $clock,

                    /** How far it moves on. */
                    private int $seconds,
                ) {}

                /**
                 * Validate, then move the clock on.
                 *
                 * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
                 * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
                 */
                #[\Override]
                public function run(CompletionState $state): StageOutcome
                {
                    $outcome = $this->stage->run($state);

                    $this->clock->advance($this->seconds);

                    return $outcome;
                }
            };
        });

        $result   = $this->complete($this->response());
        $recorded = SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count();

        self::assertSame(
            $reason === null ? ['completed', null, 1, 1] : ['failed', $reason, 0, 0],
            [$result->status->value, $result->reason, count($this->issuer->grants()), $recorded],
        );
    }

    /**
     * Assert one code was issued for the provider's subject and statement.
     *
     * @param  string  $subject
     * @param  ?string  $format
     * @return void
     */
    private function assertSignedIn(string $subject, ?string $format): void
    {
        $grant  = $this->issuer->soleGrant();
        $result = $grant->result;

        self::assertSame(
            [FakeSamlIdentityProvider::ENTITY_ID, $subject, $format, $this->connection->id, 'tenant-saml', 'saml2', ['email' => 'alice@example.test']],
            [$result->issuer, $result->subject, $result->nameIdFormat, $result->connectionId, $result->tenantId, $result->protocol, $result->attributes],
        );
        self::assertSame([
            'authenticated_at'          => '2026-11-01T09:29:00.000000Z',
            'methods'                   => [],
            'context_class'             => FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT,
            'provider_session_id'       => '_session-1',
            'provider_session_deadline' => '2026-11-01T17:30:00.000000Z',
        ], $result->authenticationContext->toArray());
        self::assertSame('2026-11-01T17:30:00+00:00', $grant->sessionNotAfter?->toIso8601String());
    }

    /**
     * Assert the one assertion recorded has the id, scope and expiry.
     *
     * @param  string  $assertionId
     * @param  string  $until
     * @return void
     */
    private function assertRecorded(string $assertionId, string $until): void
    {
        $key = ReplayRecord::samlAssertion($this->connection->id, FakeSamlIdentityProvider::ENTITY_ID, $assertionId, $this->clock->now())->key();

        self::assertSame(
            [[hash('sha256', $key), $until]],
            SingleUseKey::query()
                ->where('namespace', ReplayRecord::SAML_ASSERTION)
                ->get()
                ->map(static fn (SingleUseKey $row): array => [$row->key_digest, $row->expires_at->toIso8601String()])
                ->all(),
        );
    }

    /**
     * Complete at the assertion consumer service with the response.
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
     * Store a sign-in request with its `AuthnRequest` id and state digest.
     *
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function request(): AuthorizationRequest
    {
        return $this->makeAuthorizationRequest($this->connection, ['saml_request_id' => self::REQUEST_ID, 'state_digest' => hash('sha256', self::RELAY_STATE)]);
    }

    /**
     * A valid response from the trusted identity provider, made now.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function response(): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);
        $now       = $this->clock->now();
        $statement = [
            'instant'                 => $now->subMinute(),
            'session_index'           => '_session-1',
            'session_not_on_or_after' => $now->addHours(8),
            'class'                   => FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT,
        ];

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $now)->with(['authn_statements' => [$statement]])->inResponseTo(self::REQUEST_ID);
    }

    /**
     * Have the connection follow its metadata URL, so its fetch has a deadline.
     *
     * @return void
     */
    private function optInToRefresh(): void
    {
        $this->settings(['metadata_url' => 'https://idp.example.test/metadata.xml', 'metadata_refresh' => true]);
    }

    /**
     * Change the connection's settings.
     *
     * @param  array<string, mixed>  $settings
     * @return void
     */
    private function settings(array $settings): void
    {
        $this->connection->forceFill(['settings' => [...$this->connection->settings, ...$settings]])->save();
    }

    /**
     * Store a key or certificate of the use for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  string  $certificate
     * @param  ?string  $privateKey
     * @return void
     *
     * @throws \LogicException
     */
    private function key(KeyUse $use, ?KeyState $state, string $certificate, ?string $privateKey): void
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A certificate has a public key.'));

        (new ConnectionKey)->forceFill([
            'connection_id'   => $this->connection->id,
            'use'             => $use,
            'state'           => $state,
            'key_type'        => KeyType::RSA,
            'key_bits'        => 2048,
            'certificate'     => $certificate,
            'public_key'      => is_array($details) ? $details['key'] : '',
            'private_key'     => $privateKey === null ? null : app(SecretEncrypter::class)->encrypt($privateKey),
            'fingerprint'     => (string) openssl_x509_fingerprint($certificate, 'sha256'),
            'made_current_at' => $state === null ? null : $this->clock->now(),
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

    /**
     * The service provider's encryption key and certificate, made once.
     *
     * @return array{0: string, 1: string}
     */
    private static function spKeys(): array
    {
        return self::$spKeys ??= FakeSamlIdentityProvider::keyPair('sp.example.test');
    }
}
