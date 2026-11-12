<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\Stages\CorrelateResponse;
use SineMacula\Laravel\Sso\Completion\UnsolicitedReinitiation;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\UnsolicitedResponses;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use SineMacula\Laravel\Sso\Testing\Saml\SignatureWrapping;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\TestCase;

/**
 * Feature tests for IdP-initiated SAML re-initiation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(CorrelateResponse::class)]
#[CoversClass(UnsolicitedReinitiation::class)]
#[CoversClass(UnsolicitedResponses::class)]
final class SamlReinitiationTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The application start URL the connection sends the browser to. */
    private const string START_URL = 'https://app.example.com/sso/start';

    /** @var string The `web` application's redirect URI. */
    private const string REDIRECT_URI = 'https://app.example.com/sso';

    /** @var string The id of the assertion the responses carry. */
    private const string ASSERTION_ID = '_assertion-reinitiated-1';

    /** @var string The `AuthnRequest` id of the request a sign-in through the connection started. */
    private const string REQUEST_ID = '_request-stored-1';

    /** @var string The `RelayState` that request was started with. */
    private const string RELAY_STATE = 'the-relay-state-of-the-stored-saml-request';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider An identity provider the connection never trusts, made once. */
    private static ?FakeSamlIdentityProvider $attacker = null;

    /** @var ?array{0: string, 1: string} The service provider's encryption key and certificate, made once. */
    private static ?array $spKeys = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Handoffs\RecordingHandoffIssuer The handoff issuer. */
    private RecordingHandoffIssuer $issuer;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The SAML connection the responses arrive for. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\AuthorizationRequest A request a sign-in through the connection started, which no unsolicited response may touch. */
    private AuthorizationRequest $stored;

    /**
     * Configure IdP-initiated SAML and a trusting connection with a request.
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
        config()->set('sso.features.idp_initiated', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => self::REDIRECT_URI, 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'tenant_id' => 'tenant-saml',
            'protocol'  => 'saml2',
            'enabled'   => true,
            'settings'  => [
                'idp_entity_id'           => FakeSamlIdentityProvider::ENTITY_ID,
                'sso_url'                 => FakeSamlIdentityProvider::SSO_URL,
                'idp_initiated'           => true,
                'idp_initiated_start_url' => self::START_URL,
            ],
            'attribute_mapping' => ['email' => 'email'],
        ]);

        $this->key(KeyUse::IDP_SIGNING, null, self::idp()->certificate(), null);
        $this->key(KeyUse::SP_ENCRYPTION, KeyState::CURRENT, self::spKeys()[1], self::spKeys()[0]);

        $this->stored = $this->makeAuthorizationRequest($this->connection, ['saml_request_id' => self::REQUEST_ID, 'state_digest' => hash('sha256', self::RELAY_STATE)]);
    }

    /**
     * A connection that does not allow it is `unsolicited_not_allowed`.
     *
     * @return void
     */
    public function testAConnectionThatDoesNotAllowItRejectsWithUnsolicitedNotAllowed(): void
    {
        $this->settings(['idp_initiated' => false]);

        $this->assertRejected(FailureReason::UNSOLICITED_NOT_ALLOWED, $this->complete($this->response()));
    }

    /**
     * Rows of `[start URL, expected]`, `{id}` being the connection's id.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideStartUrls(): iterable
    {
        yield 'no query' => [self::START_URL, self::START_URL . '?connection={id}'];
        yield 'a query of its own' => [self::START_URL . '?tenant=acme', self::START_URL . '?tenant=acme&connection={id}'];
    }

    /**
     * A valid unsolicited response is re-initiated to the start URL.
     *
     * @param  string  $startUrl
     * @param  string  $expected
     * @return void
     */
    #[DataProvider('provideStartUrls')]
    public function testAValidUnsolicitedResponseIsReinitiated(string $startUrl, string $expected): void
    {
        $this->settings(['idp_initiated_start_url' => $startUrl]);

        $result = $this->complete($this->response());

        self::assertSame(
            ['reinitiated', null, str_replace('{id}', $this->connection->id, $expected), null, null, null],
            [$result->status->value, $result->reason, $result->startUrl, $result->redirectUri, $result->reference, $result->handoff],
        );
        $this->assertRecorded();
        $this->assertNoRequestTouched();
    }

    /**
     * A second post of the same response is `replayed`.
     *
     * @return void
     */
    public function testASecondPostOfTheSameResponseIsReplayed(): void
    {
        $response = $this->response();

        self::assertTrue($this->complete($response)->isReinitiated());

        $second = $this->complete($response);

        self::assertSame([true, FailureReason::REPLAYED, null], [$second->isRejected(), $second->reason, $second->startUrl]);
        $this->assertRecorded();
        $this->assertNoRequestTouched();
    }

    /**
     * Rows of `[change, reason]` breaking a rule of a solicited response.
     *
     * @return iterable<string, array{
     *     0: \Closure(\SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse): \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse,
     *     1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason
     * }>
     */
    public static function provideBrokenRules(): iterable
    {
        yield 'another audience' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['audiences' => [['https://other.example.test/saml']]]),
            FailureReason::AUDIENCE_MISMATCH,
        ];
        yield 'expired conditions' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with([
                'not_before'      => CarbonImmutable::parse('2026-11-01T09:20:00Z'),
                'not_on_or_after' => CarbonImmutable::parse('2026-11-01T09:25:00Z'),
            ]),
            FailureReason::ASSERTION_EXPIRED,
        ];
        yield 'an assertion signed by an attacker' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->signedBy(self::attacker()->signer()),
            FailureReason::SIGNATURE_INVALID,
        ];
        yield 'an unsigned assertion' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->signed(false, false),
            FailureReason::SIGNATURE_INVALID,
        ];
        yield 'another recipient' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['confirmations' => [self::confirmation('https://sp.example.test/other')]]),
            FailureReason::RECIPIENT_MISMATCH,
        ];
        yield 'a transient NameID' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['name_id_format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient']),
            FailureReason::SUBJECT_INVALID,
        ];

        foreach (SignatureWrapping::VARIANTS as $variant) {
            yield 'signature wrapping ' . $variant => [
                static fn (FakeSamlResponse $response): FakeSamlResponse => $response->wrapped($variant),
                FailureReason::RESPONSE_INVALID,
            ];
        }
    }

    /**
     * Every rule of a solicited response still holds.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse): \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $change
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideBrokenRules')]
    public function testEverySolicitedRuleStillHolds(\Closure $change, FailureReason $reason): void
    {
        $this->assertRejected($reason, $this->complete($change($this->response())));
    }

    /**
     * An `InResponseTo` anywhere is never unsolicited.
     *
     * @return void
     */
    public function testAnInResponseToAnywhereIsNeverUnsolicited(): void
    {
        $confirmed = $this->response()->inResponseTo('_request-never-stored')->with(['in_response_to' => null]);

        $this->assertRejected(FailureReason::REQUEST_UNKNOWN, $this->complete($confirmed));
        $this->assertRejected(FailureReason::REQUEST_UNKNOWN, $this->complete($confirmed->encryptedFor(self::spKeys()[1])));
    }

    /**
     * An `InResponseTo` naming a stored request completes that request.
     *
     * @return void
     */
    public function testAnInResponseToNamingAStoredRequestIsSolicited(): void
    {
        $result = $this->complete($this->response()->inResponseTo(self::REQUEST_ID), self::RELAY_STATE);

        self::assertSame(
            ['completed', self::REDIRECT_URI, $this->stored->reference, null],
            [$result->status->value, $result->redirectUri, $result->reference?->value, $result->startUrl],
        );
        self::assertCount(1, $this->issuer->grants());
        self::assertNotNull(AuthorizationRequest::query()->whereKey($this->stored->id)->sole()->consumed_at);
        $this->assertRecorded();
    }

    /**
     * A `RelayState` URL is never the target.
     *
     * @return void
     */
    public function testARelayStateUrlIsNeverTheTarget(): void
    {
        $result = $this->complete($this->response(), 'https://attacker.example.test/steal');

        self::assertSame(['reinitiated', self::START_URL . '?connection=' . $this->connection->id], [$result->status->value, $result->startUrl]);
    }

    /**
     * Expired metadata rejects with `metadata_expired`.
     *
     * @return void
     */
    public function testExpiredMetadataRejectsWithMetadataExpired(): void
    {
        $this->optInToRefresh();
        $this->connection->forceFill(['metadata_fetched_at' => $this->clock->now()->subHours(2), 'metadata_valid_until' => $this->clock->now()->subHour()])->save();

        $this->assertRejected(FailureReason::METADATA_EXPIRED, $this->complete($this->response()));
    }

    /**
     * A connection disabled after validation is refused under the lock.
     *
     * @return void
     */
    public function testAConnectionDisabledAfterValidationIsUnavailable(): void
    {
        $id      = $this->connection->id;
        $pending = $this->afterValidation(static function () use ($id): void {
            Connection::query()->whereKey($id)->sole()->forceFill(['enabled' => false])->save();
        });

        $this->assertRejected(FailureReason::CONNECTION_UNAVAILABLE, $this->complete($this->response()));
        self::assertCount(0, $pending);
    }

    /**
     * A trust version moved after validation is refused under the lock.
     *
     * @return void
     */
    public function testATrustVersionMovedAfterValidationIsUnavailable(): void
    {
        $id      = $this->connection->id;
        $pending = $this->afterValidation(static function () use ($id): void {
            Connection::query()->whereKey($id)->sole()->increment('trust_version');
        });

        $this->assertRejected(FailureReason::CONNECTION_UNAVAILABLE, $this->complete($this->response()));
        self::assertCount(0, $pending);
    }

    /**
     * A connection gone after validation is refused under the lock.
     *
     * @return void
     */
    public function testAConnectionGoneAfterValidationIsUnavailable(): void
    {
        $id      = $this->connection->id;
        $pending = $this->afterValidation(static function () use ($id): void {
            DB::connection(StorageConnection::name())->table(StorageConnection::table('connections.table'))->where('id', $id)->delete();
        });

        $this->assertRejected(FailureReason::CONNECTION_UNAVAILABLE, $this->complete($this->response()));
        self::assertCount(0, $pending);
    }

    /**
     * Rows of `[settings, reason]` changed after validation.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideSettingsChangedAfterValidation(): iterable
    {
        yield 'IdP-initiated sign-in turned off' => [['idp_initiated' => false], FailureReason::UNSOLICITED_NOT_ALLOWED];
        yield 'the start URL changed' => [['idp_initiated_start_url' => 'https://app.example.com/sso/other'], FailureReason::CONNECTION_UNAVAILABLE];
    }

    /**
     * Settings changed after validation are refused under the lock.
     *
     * @param  array<string, mixed>  $settings
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideSettingsChangedAfterValidation')]
    public function testSettingsChangedAfterValidationAreRefusedUnderTheLock(array $settings, FailureReason $reason): void
    {
        $id      = $this->connection->id;
        $version = Connection::query()->whereKey($id)->sole()->trust_version;
        $pending = $this->afterValidation(static function () use ($id, $settings): void {
            $row = Connection::query()->whereKey($id)->sole();
            $row->forceFill(['settings' => [...$row->settings, ...$settings]])->save();
        });

        $this->assertRejected($reason, $this->complete($this->response()));
        self::assertCount(0, $pending);
        self::assertSame($version, Connection::query()->whereKey($id)->sole()->trust_version);
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
        $this->afterValidation(static function () use ($clock, $seconds): void {
            $clock->advance($seconds);
        });

        $result = $this->complete($this->response());

        if ($reason !== null) {
            $this->assertRejected($reason, $result);

            return;
        }

        self::assertSame(['reinitiated', self::START_URL . '?connection=' . $this->connection->id], [$result->status->value, $result->startUrl]);
        $this->assertNoRequestTouched();
    }

    /**
     * With the feature turned off, the connection is refused under the lock.
     *
     * @return void
     */
    public function testTheFeatureTurnedOffMakesTheConnectionUnavailable(): void
    {
        config()->set('sso.features.idp_initiated', false);

        $this->assertRejected(FailureReason::CONNECTION_UNAVAILABLE, $this->complete($this->response()));
    }

    /**
     * Assert a rejection with the reason, no target and nothing touched.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return void
     */
    private function assertRejected(FailureReason $reason, CompletionResult $result): void
    {
        self::assertSame(['rejected', $reason, null, null], [$result->status->value, $result->reason, $result->startUrl, $result->redirectUri]);
        self::assertSame(0, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
        $this->assertNoRequestTouched();
    }

    /**
     * Assert no request was consumed, completed, voided or created.
     *
     * @return void
     */
    private function assertNoRequestTouched(): void
    {
        $row = AuthorizationRequest::query()->whereKey($this->stored->id)->sole();

        self::assertSame([null, null, null], [$row->consumed_at, $row->completed_at, $row->voided_at]);
        self::assertSame(1, AuthorizationRequest::query()->count());
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * Assert the response's assertion is recorded once, scoped and timed.
     *
     * @return void
     */
    private function assertRecorded(): void
    {
        $key = ReplayRecord::samlAssertion($this->connection->id, FakeSamlIdentityProvider::ENTITY_ID, self::ASSERTION_ID, $this->clock->now())->key();

        self::assertSame(
            [[hash('sha256', $key), '2026-11-01T09:36:00+00:00']],
            SingleUseKey::query()
                ->where('namespace', ReplayRecord::SAML_ASSERTION)
                ->get()
                ->map(static fn (SingleUseKey $row): array => [$row->key_digest, $row->expires_at->toIso8601String()])
                ->all(),
        );
    }

    /**
     * Run the change once before the re-initiation's transaction; answers what
     * is still to run.
     *
     * @param  \Closure(): void  $change
     * @return \ArrayObject<int, \Closure(): void>
     */
    private function afterValidation(\Closure $change): \ArrayObject
    {
        $pending = new \ArrayObject([$change]);

        DB::connection(StorageConnection::name())->beforeStartingTransaction(static function () use ($pending): void {

            $next = $pending[0] ?? null;

            if ($next === null) {
                return;
            }

            unset($pending[0]);
            $next();
        });

        return $pending;
    }

    /**
     * Complete at the assertion consumer service with the `RelayState`, if any.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @param  ?string  $relayState
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(FakeSamlResponse $response, ?string $relayState = null): CompletionResult
    {
        return app(CompletionService::class)->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $this->connection->id,
            $response->completionRequest($relayState),
            Clients::browser(),
        );
    }

    /**
     * A valid unsolicited response from the trusted identity provider.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function response(): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->clock->now())->with(['assertion_id' => self::ASSERTION_ID]);
    }

    /**
     * A bearer confirmation valid for five minutes, answering no request.
     *
     * @param  string  $recipient
     * @return array{method: string, data: bool, recipient: string, not_before: null, not_on_or_after: \Carbon\CarbonImmutable, in_response_to: null}
     */
    private static function confirmation(string $recipient): array
    {
        return [
            'method'          => FakeSamlResponse::BEARER,
            'data'            => true,
            'recipient'       => $recipient,
            'not_before'      => null,
            'not_on_or_after' => CarbonImmutable::parse('2026-11-01T09:35:00Z'),
            'in_response_to'  => null,
        ];
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
     * A provider of the same entity id the connection never trusts.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function attacker(): FakeSamlIdentityProvider
    {
        return self::$attacker ??= new FakeSamlIdentityProvider;
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
