<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Carbon\CarbonImmutable;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
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
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\TestCase;

/**
 * Feature tests for IdP-initiated re-initiation (SSO-5.8, SSO-6.11, SSO-2.8)
 * through the public completion helper, with the fake identity provider's
 * unsolicited responses: a connection that does not allow it refuses with
 * `unsolicited_not_allowed`; one that does sends the browser to its start URL
 * naming the connection, with and without a query of its own, records the
 * assertion once and refuses a second post as `replayed`; every rule of a
 * solicited response still holds; an `InResponseTo` anywhere is never
 * unsolicited, and one naming a stored request completes that request; the
 * `RelayState` is never the target; expired metadata refuses; and a connection
 * disabled, its IdP-initiated opt-in or start URL changed, its metadata lapsed,
 * or IdP-initiated sign-in turned off, after validation is refused under the
 * lock. No authorisation request is ever consumed or created and no code issued
 * by a re-initiation.
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
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

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
     * Bind a fixed clock, the recording issuer and a request from an IP
     * address, configure SAML, IdP-initiated sign-in, the endpoints and the
     * application, and create the tables, a connection that allows
     * IdP-initiated sign-in and trusts the identity provider, and a request in
     * flight through it.
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

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::migration(self::SINGLE_USE_MIGRATION)->up(); // @phpstan-ignore method.notFound
        self::migration(self::RATE_LIMITS_MIGRATION)->up(); // @phpstan-ignore method.notFound

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
     * A connection that does not allow IdP-initiated sign-in rejects a valid
     * unsolicited response with `unsolicited_not_allowed`, recording nothing.
     *
     * @return void
     */
    public function testAConnectionThatDoesNotAllowItRejectsWithUnsolicitedNotAllowed(): void
    {
        $this->settings(['idp_initiated' => false]);

        $this->assertRejected(FailureReason::UNSOLICITED_NOT_ALLOWED, $this->complete($this->response()));
    }

    /**
     * Rows of `[start URL, expected]`: the start URL set, and the URL the
     * browser is sent to, with `{id}` the connection's id.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideStartUrls(): iterable
    {
        yield 'no query' => [self::START_URL, self::START_URL . '?connection={id}'];
        yield 'a query of its own' => [self::START_URL . '?tenant=acme', self::START_URL . '?tenant=acme&connection={id}'];
    }

    /**
     * A valid unsolicited response at a connection that allows it is
     * re-initiated: the browser goes to exactly the start URL naming the
     * connection; the assertion is recorded once until its last acceptance
     * moment; no request is consumed or created and no code is issued.
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
     * A second post of the same unsolicited response is rejected with
     * `replayed`, and the assertion is still recorded once.
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
     * Rows of `[change, reason]`: a valid unsolicited response changed so a
     * rule of a solicited response breaks, and the reason it is refused for.
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
     * Every rule of a solicited response still holds for an unsolicited one:
     * each broken rule rejects it with its reason, recording nothing.
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
     * An `InResponseTo` anywhere is never unsolicited: on the bearer
     * confirmation alone it names a request that is not stored, and inside the
     * encrypted assertion alone the unsolicited profile finds it; each is
     * rejected with `request_unknown`, recording nothing.
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
     * An `InResponseTo` naming a stored request is solicited, never
     * unsolicited, even at a connection that allows IdP-initiated sign-in: the
     * request is consumed and completed, and a code issued for it.
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
     * A `RelayState` naming a URL is never the target: the browser goes to the
     * start URL alone.
     *
     * @return void
     */
    public function testARelayStateUrlIsNeverTheTarget(): void
    {
        $result = $this->complete($this->response(), 'https://attacker.example.test/steal');

        self::assertSame(['reinitiated', self::START_URL . '?connection=' . $this->connection->id], [$result->status->value, $result->startUrl]);
    }

    /**
     * A connection whose refreshed metadata has expired rejects the response
     * with `metadata_expired`, recording nothing.
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
     * A connection disabled once the response is validated, before the
     * connection is locked, is refused under the lock with
     * `connection_unavailable`, recording nothing.
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
     * A connection whose trust version moves once the response is validated is
     * refused under the lock with `connection_unavailable`, recording nothing,
     * though it is still usable.
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
     * A connection whose row goes once the response is validated is refused
     * under the lock with `connection_unavailable`.
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
     * Rows of `[settings, reason]`: the connection's settings changed once the
     * response is validated, and the reason it is refused for under the lock.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideSettingsChangedAfterValidation(): iterable
    {
        yield 'IdP-initiated sign-in turned off' => [['idp_initiated' => false], FailureReason::UNSOLICITED_NOT_ALLOWED];
        yield 'the start URL changed' => [['idp_initiated_start_url' => 'https://app.example.com/sso/other'], FailureReason::CONNECTION_UNAVAILABLE];
    }

    /**
     * A connection whose IdP-initiated opt-in is turned off, or whose start URL
     * changes, once the response is validated is refused under the lock with
     * the reason, recording nothing, though its trust version never moved.
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
     * Rows of `[seconds, reason]`: the seconds the clock moves on once the
     * response is validated, with the connection's refreshed metadata valid for
     * a minute, and the reason it is refused for under the lock, if any.
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
     * Refreshed metadata that lapses once the response is validated refuses it
     * under the lock with `metadata_expired`, recording nothing; a second
     * before it lapses, the response is re-initiated.
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
     * With IdP-initiated sign-in turned off for the application, a connection
     * still holding it on is incomplete: its response is validated as the
     * connection holds it, then refused under the lock with
     * `connection_unavailable`, recording nothing.
     *
     * @return void
     */
    public function testTheFeatureTurnedOffMakesTheConnectionUnavailable(): void
    {
        config()->set('sso.features.idp_initiated', false);

        $this->assertRejected(FailureReason::CONNECTION_UNAVAILABLE, $this->complete($this->response()));
    }

    /**
     * Assert the result is rejected with the reason and no target, nothing is
     * recorded, and no request is touched.
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
     * Assert the request in flight was neither consumed, completed nor voided,
     * no other request was created, and no code was issued.
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
     * Assert the one assertion recorded is the responses', scoped by the
     * connection and the identity provider, until its last acceptance moment.
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
     * Run the change once, just before the next transaction on the storage
     * connection starts: the re-initiation's, which it opens only once the
     * response is validated. Answers what is still to run, empty once it ran.
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
     * Complete at the connection's assertion consumer service with the
     * response, posted with the `RelayState` given, if any.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @param  ?string  $relayState
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(FakeSamlResponse $response, ?string $relayState = null): CompletionResult
    {
        return app(CompletionService::class)->assertionConsumerService($this->connection->id, $response->completionRequest($relayState));
    }

    /**
     * A valid unsolicited response from the trusted identity provider, made
     * now, for the connection's service provider.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function response(): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->clock->now())->with(['assertion_id' => self::ASSERTION_ID]);
    }

    /**
     * A bearer confirmation for the recipient, valid for five minutes from the
     * tests' now and answering no request.
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
     * An identity provider of the same entity id the connection never trusts,
     * made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function attacker(): FakeSamlIdentityProvider
    {
        return self::$attacker ??= new FakeSamlIdentityProvider;
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
