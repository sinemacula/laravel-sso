<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\CompletionState;
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
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\TestCase;

/**
 * Feature tests for completing a SAML sign-in at the assertion consumer service
 * (SSO-5.3, SSO-6.2 to SSO-6.10, SSO-2.8), through the public completion helper
 * with the fake identity provider's responses: a signed response, a signed
 * assertion, an encrypted assertion with AES-GCM and with AES-CBC by opt-in,
 * and an attribute subject each complete, with the claims, the encoded subject,
 * the authentication context, the provider deadline and the replay record's
 * expiry exactly; a second post of the same response finds its request
 * consumed; and expired metadata refuses the completion, as does metadata that
 * lapses once the response is validated, under the lock.
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
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

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
     * Bind a fixed clock, the recording issuer and a request from an IP
     * address, configure SAML, the endpoints and the application, and create
     * the tables and a connection that trusts the identity provider.
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

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::migration(self::SINGLE_USE_MIGRATION)->up(); // @phpstan-ignore method.notFound
        self::migration(self::RATE_LIMITS_MIGRATION)->up(); // @phpstan-ignore method.notFound

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
     * A response whose assertion is signed completes: a code for the `web`
     * application with the request's reference; the result's issuer, encoded
     * subject, format, mapped email and authentication context exactly; the
     * session limited by the provider's deadline; the assertion recorded until
     * its last acceptance moment; and the request consumed and completed.
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
     * A response signed in its envelope alone completes when the connection
     * does not want the assertion signed.
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
     * An assertion encrypted with RSA-OAEP and AES-128-GCM completes when the
     * connection requires encryption, decrypted with its current key.
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
     * An assertion encrypted with AES-128-CBC completes once the connection
     * lists it, inside a response whose signature is verified first.
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
     * A subject taken from an attribute completes with the attribute's encoding
     * and no NameID format, whatever the `NameID` is.
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
     * A second post of a completed response finds its request consumed: it is
     * rejected with `request_unknown`, and nothing more is recorded or issued.
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
     * A connection whose refreshed metadata has expired refuses the completion
     * with `metadata_expired` once its request is consumed, recording nothing.
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
     * Rows of `[seconds, reason]`: the seconds the clock moves on once the
     * response is validated, with the connection's refreshed metadata valid for
     * a minute, and the reason the completion is refused for under the lock, if
     * any.
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
     * Refreshed metadata that lapses once the response is validated refuses the
     * completion under the lock with `metadata_expired`, recording nothing and
     * issuing no code; a second before it lapses, the completion completes.
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
     * Assert one code was issued for a result of the identity provider with the
     * subject and format, the mapped email, the default statement's
     * authentication context, and the session limited by its deadline.
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
     * Assert the one assertion recorded is the one with the id, scoped by the
     * connection and the identity provider, until the instant.
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
     * Complete at the connection's assertion consumer service with the
     * response, posted with the request's `RelayState`.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(FakeSamlResponse $response): CompletionResult
    {
        return app(CompletionService::class)->assertionConsumerService($this->connection->id, $response->completionRequest(self::RELAY_STATE));
    }

    /**
     * Store the request a sign-in through the connection started: its
     * `AuthnRequest` id and its `RelayState`'s digest.
     *
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function request(): AuthorizationRequest
    {
        return $this->makeAuthorizationRequest($this->connection, ['saml_request_id' => self::REQUEST_ID, 'state_digest' => hash('sha256', self::RELAY_STATE)]);
    }

    /**
     * A valid response from the trusted identity provider, made now, for the
     * connection's service provider, answering the request, with a fixed
     * authentication statement.
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
     * Have the connection follow its metadata URL, so that what was fetched
     * holds a deadline.
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
     * The service provider's encryption key and certificate, made once for the
     * class.
     *
     * @return array{0: string, 1: string}
     */
    private static function spKeys(): array
    {
        return self::$spKeys ??= FakeSamlIdentityProvider::keyPair('sp.example.test');
    }

    /**
     * The shipped migration of the file.
     *
     * @param  string  $file
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function migration(string $file): Migration
    {
        return require dirname(__DIR__, 3) . $file;
    }
}
