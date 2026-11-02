<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\ResponseCorrelator;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\TestCase;

/**
 * The library spike's 40 adversarial fixtures (BL-0A), each posted through the
 * public completion helper at the assertion consumer service of a connection
 * set up as the fixtures were signed for: the identity provider's entity id and
 * certificate, the service provider's entity id, assertion consumer service and
 * encryption key, and a stored request with the fixtures' `AuthnRequest` id
 * (SSO-6.1 to SSO-6.11, `docs/design/saml-library.md`).
 *
 * The connection asks for no assertion signature of its own, the most
 * permissive policy, so a refusal is never the policy's. Each fixture has the
 * outcome the manifest records for the package: one that is read completes the
 * flow with the legitimate subject, or the whole signed value of a `NameID` a
 * comment splits; one that is refused fails with the manifest's reason, but a
 * document the hardened parse refuses names no request, so it is
 * `request_unknown`. A refusal reports exactly one `FlowFailed`, records no
 * assertion, makes no link or handoff, and never reads an external entity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-type Fixture array{name: string, expect: string, package: array{outcome: string, subject?: string, reason?: string, detail?: string}}
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(ResponseCorrelator::class)]
#[CoversClass(AssertionValidator::class)]
final class SamlFixtureCompletionTest extends TestCase
{
    use CapturesLogs, RecordsEventSequences, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The fixtures' directory. */
    private const string FIXTURES = __DIR__ . '/../../Fixtures/Saml';

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The `RelayState` the request was started with. */
    private const string RELAY_STATE = 'the-relay-state-of-the-fixtures-request';

    /** @var string What the external entity fixtures would read. */
    private const string SECRET = 'XXE-SECRET';

    /** @var string AES-128-CBC. */
    private const string AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';

    /** @var string The detail of a document the hardened parse refuses. */
    private const string UNPARSEABLE = 'unparseable';

    /** @var \Tests\Fixtures\Handoffs\RecordingHandoffIssuer The handoff issuer. */
    private RecordingHandoffIssuer $issuer;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the fixtures were signed for. */
    private Connection $connection;

    /**
     * Freeze the clock half a minute after the fixtures were issued, bind the
     * recording issuer and the fixtures' endpoints, create the tables, the
     * connection with its trusted certificate and encryption key, and the
     * request; capture logs and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->issuer = new RecordingHandoffIssuer;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T12:00:30Z'));
        $this->app?->instance(HandoffIssuer::class, $this->issuer);
        $this->app?->instance(EndpointResolver::class, self::endpointResolver());
        $this->app?->instance('request', Request::create('/saml/acs', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.encrypted_assertions', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::migration(self::SINGLE_USE_MIGRATION)->up(); // @phpstan-ignore method.notFound
        self::migration(self::RATE_LIMITS_MIGRATION)->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection([
            'protocol'          => 'saml2',
            'enabled'           => true,
            'settings'          => ['idp_entity_id' => self::manifest()['idp_entity_id'], 'sso_url' => 'https://idp.example.test/saml/sso', 'want_assertions_signed' => false],
            'attribute_mapping' => ['email' => 'email'],
        ]);

        $this->key(KeyUse::IDP_SIGNING, null, self::file('keys/idp.crt'), null);
        $this->key(KeyUse::SP_ENCRYPTION, KeyState::CURRENT, self::file('keys/sp.crt'), self::file('keys/sp.key'));

        $this->makeAuthorizationRequest($this->connection, [
            'saml_request_id' => self::manifest()['request_id'],
            'state_digest'    => hash('sha256', self::RELAY_STATE),
        ]);

        $this->captureLogs();
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
     * Rows of `[fixture]`: each of the 40 fixtures, as the manifest records it.
     *
     * @return iterable<string, array{0: Fixture}>
     */
    public static function provideFixtures(): iterable
    {
        foreach (self::manifest()['fixtures'] as $fixture) {
            yield $fixture['name'] => [$fixture];
        }
    }

    /**
     * The fixture completes the flow with its subject, or is refused cleanly
     * with its reason, as the manifest records for the package.
     *
     * @param  Fixture  $fixture
     * @return void
     */
    #[DataProvider('provideFixtures')]
    public function testEachFixtureHasItsOutcomeThroughTheCompletion(array $fixture): void
    {
        $result = $this->complete($fixture['name']);

        $this->assertNothingLoggedContains(self::SECRET);

        if ($fixture['package']['outcome'] === 'read') {
            $this->assertCompletedFor($result, $fixture['package']['subject'] ?? '');

            return;
        }

        $reason = ($fixture['package']['detail'] ?? null) === self::UNPARSEABLE
            ? FailureReason::REQUEST_UNKNOWN
            : FailureReason::from($fixture['package']['reason'] ?? '');

        self::assertSame($reason, $result->reason, $fixture['name']);
        self::assertTrue($fixture['expect'] !== 'accept' || $fixture['name'] === '04-valid-encrypted-oaep-gcm', "{$fixture['name']} must be accepted.");
        $this->assertRefusedCleanly($reason);
    }

    /**
     * With AES-CBC listed, the fixture encrypted with RSA-OAEP and AES-128-CBC
     * in a signed response completes the flow.
     *
     * @return void
     */
    public function testAesCbcCompletesWhenListed(): void
    {
        $this->settings(['encryption_algorithms' => self::withAesCbc()]);

        $this->assertCompletedFor($this->complete('64-encrypted-oaep-cbc'), self::manifest()['subject']);
    }

    /**
     * RSA 1.5 key transport is refused even with AES-CBC listed, with the one
     * decryption failure.
     *
     * @return void
     */
    public function testRsaOnePointFiveIsRefusedEvenWithAesCbcListed(): void
    {
        $this->settings(['encryption_algorithms' => self::withAesCbc()]);

        self::assertSame(FailureReason::DECRYPTION_FAILED, $this->complete('62-encrypted-rsa15-cbc')->reason);
        $this->assertRefusedCleanly(FailureReason::DECRYPTION_FAILED);
    }

    /**
     * Under the default policy, which wants the assertion's own signature, a
     * fixture signed only over the response is refused.
     *
     * @return void
     */
    public function testTheDefaultPolicyRefusesAnAssertionSignedOnlyByTheResponse(): void
    {
        $this->settings(['want_assertions_signed' => true]);

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->complete('01-valid-response-signed')->reason);
        $this->assertRefusedCleanly(FailureReason::SIGNATURE_INVALID);
    }

    /**
     * Under the default policy, a fixture whose assertion carries its own
     * signature completes the flow.
     *
     * @return void
     */
    public function testTheDefaultPolicyCompletesAnAssertionSignedByItself(): void
    {
        $this->settings(['want_assertions_signed' => true]);

        $this->assertCompletedFor($this->complete('03-valid-both-signed'), self::manifest()['subject']);
    }

    /**
     * Assert the completion signed the subject in: one assertion recorded and
     * one handoff granted for the persistent `NameID` with the value.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @param  string  $subject
     * @return void
     */
    private function assertCompletedFor(CompletionResult $result, string $subject): void
    {
        $encoded = 'v1|7:name_id|52:' . FakeSamlResponse::PERSISTENT . '|-|-|' . strlen($subject) . ':' . $subject;

        self::assertTrue($result->isCompleted(), (string) $result->reason?->value);
        self::assertSame([$encoded], array_map(static fn ($grant): string => $grant->result->subject, $this->issuer->grants()));
        self::assertSame(1, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
    }

    /**
     * Assert the completion reported exactly one `FlowFailed` for the reason
     * and the assertion flow and nothing else, recorded no assertion, and made
     * no link or handoff.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    private function assertRefusedCleanly(FailureReason $reason): void
    {
        $this->assertExactlyOneFailure(Flow::ASSERTION, $reason);
        $this->assertEventSequence([FlowFailed::class]);

        self::assertSame(0, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
        self::assertSame(0, Link::query()->count());
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * Post the fixture, with the request's `RelayState`, to the connection's
     * assertion consumer service.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(string $name): CompletionResult
    {
        $posted = new CompletionRequest('POST', '', ['SAMLResponse' => base64_encode(self::fixture($name)), 'RelayState' => self::RELAY_STATE]);

        return app(CompletionService::class)->assertionConsumerService($this->connection->id, $posted);
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
        $details = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A fixture certificate has a public key.'));

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
            'made_current_at' => $state === null ? null : app(Clock::class)->now(),
        ])->save();
    }

    /**
     * The default encryption algorithms with AES-128-CBC listed too.
     *
     * @return list<string>
     */
    private static function withAesCbc(): array
    {
        return [...Saml2Settings::KEY_TRANSPORT_ALGORITHMS, ...Saml2Settings::DATA_ENCRYPTION_ALGORITHMS, self::AES128_CBC];
    }

    /**
     * An endpoint resolver answering the endpoints the fixtures were signed
     * for, whatever the connection.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\EndpointResolver
     */
    private static function endpointResolver(): EndpointResolver
    {
        return new class (self::manifest()['acs_url'], self::manifest()['sp_entity_id']) implements EndpointResolver {
            /**
             * Constructor.
             *
             * @param  string  $assertionConsumerService
             * @param  string  $entityId
             */
            public function __construct(

                /** The assertion consumer service the fixtures are addressed to. */
                private readonly string $assertionConsumerService,

                /** The service provider entity id the fixtures name as their audience. */
                private readonly string $entityId,
            ) {}

            /**
             * The fixtures' endpoints.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints
             */
            #[\Override]
            public function endpoints(SsoConnection $connection): ConnectionEndpoints
            {
                unset($connection);

                $jwks = 'https://sp.example.test/saml/jwks';

                return new ConnectionEndpoints($this->assertionConsumerService, 'https://sp.example.test/saml/callback', $this->entityId, $this->entityId, $jwks);
            }
        };
    }

    /**
     * The fixture's bytes, with the fixtures' directory in place of its
     * placeholder, in the fixture's own encoding.
     *
     * @param  string  $name
     * @return string
     */
    private static function fixture(string $name): string
    {
        $xml       = self::file('responses/' . $name . '.xml');
        $directory = (string) realpath(self::FIXTURES);

        if (!str_starts_with($xml, "\xFF\xFE")) {
            return str_replace('{{FIXTURES}}', $directory, $xml);
        }

        $utf8 = str_replace('{{FIXTURES}}', $directory, mb_convert_encoding(substr($xml, 2), 'UTF-8', 'UTF-16LE'));

        return "\xFF\xFE" . mb_convert_encoding($utf8, 'UTF-16LE', 'UTF-8');
    }

    /**
     * The contents of a file in the fixtures' directory.
     *
     * @param  string  $path
     * @return string
     */
    private static function file(string $path): string
    {
        return (string) file_get_contents(self::FIXTURES . '/' . $path);
    }

    /**
     * The fixtures' manifest.
     *
     * @return array{idp_entity_id: string, sp_entity_id: string, acs_url: string, request_id: string, subject: string, fixtures: list<Fixture>}
     */
    private static function manifest(): array
    {
        /** @var array{idp_entity_id: string, sp_entity_id: string, acs_url: string, request_id: string, subject: string, fixtures: list<Fixture>} */
        return json_decode(self::file('manifest.json'), true, flags: JSON_THROW_ON_ERROR);
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
