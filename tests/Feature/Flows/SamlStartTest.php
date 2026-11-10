<?php

declare(strict_types = 1);

namespace Tests\Feature\Flows;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Saml2\AuthnRequests;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for starting a SAML flow through the public start service
 * (SSO-5.1, SSO-5.3, SSO-2.8, SSO-10.2): the stored request's `saml_request_id`
 * is the `ID` of the request sent, by either binding, and its state digest is
 * the digest of the `RelayState` sent; the start reports
 * `AuthorizationRequestStarted` once, naming neither; two starts send distinct
 * ids; and with expired metadata the start is refused with `metadata_expired`,
 * reporting one `FlowFailed` and storing nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthnRequests::class)]
#[CoversClass(AuthorizationRequestService::class)]
final class SamlStartTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The identity provider's single sign-on URL. */
    private const string SSO_URL = 'https://idp.example.com/saml/sso';

    /** @var string The SAML protocol namespace. */
    private const string NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';

    /** @var ?array{0: string, 1: string} The service provider's signing key and certificate, made once. */
    private static ?array $spKeys = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /**
     * Bind a fixed clock and a request from the client, switch SAML on,
     * register the application and the endpoints, create the tables, and record
     * events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance('request', Request::create('/auth/sso/authorization-requests', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.saml2', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $this->usePackageTables();

        $this->startRecordingEvents();
    }

    /**
     * A redirect start stores the `ID` of the request it sends as
     * `saml_request_id`, and the digest of its `RelayState` as the state
     * digest, and reports `AuthorizationRequestStarted` once, naming neither.
     *
     * @return void
     */
    public function testARedirectStartStoresTheIdOfTheRequestSent(): void
    {
        $connection = $this->saml();
        $result     = $this->startFlow($connection);

        self::assertTrue($result->isStarted());
        self::assertTrue((bool) $result->navigation?->isRedirect());

        parse_str((string) parse_url($result->navigation->url(), PHP_URL_QUERY), $query);

        $relayState = $query['RelayState']  ?? null;
        $message    = $query['SAMLRequest'] ?? null;

        self::assertIsString($relayState);
        self::assertIsString($message);

        $id  = self::requestIdOf((string) gzinflate((string) base64_decode($message, true)));
        $row = AuthorizationRequest::query()->sole();

        self::assertSame([$id, $connection->id, hash('sha256', $relayState), null, false], [
            $row->saml_request_id,
            $row->connection_id,
            $row->state_digest,
            $row->expected_issuer,
            $row->issuer_required,
        ]);
        self::assertSame($result->reference?->value, $row->reference);
        self::assertNotSame($result->reference->value, $relayState);

        $this->assertStartedOnceNaming($result, $id, $relayState);
    }

    /**
     * A signed post start stores the `ID` of the request it posts, and reports
     * `AuthorizationRequestStarted` once, naming neither it nor the state.
     *
     * @return void
     */
    public function testASignedPostStartStoresTheIdOfTheRequestSent(): void
    {
        $connection = $this->saml(['sso_binding' => 'http_post', 'sign_authn_requests' => true]);

        $this->signingKey($connection);

        $result = $this->startFlow($connection);
        $fields = (array) $result->navigation?->fields();

        self::assertTrue((bool) $result->navigation?->isPost());
        self::assertSame(['SAMLRequest', 'RelayState'], array_keys($fields));

        $id  = self::requestIdOf((string) base64_decode($fields['SAMLRequest'], true));
        $row = AuthorizationRequest::query()->sole();

        self::assertSame($id, $row->saml_request_id);
        self::assertSame(hash('sha256', $fields['RelayState']), $row->state_digest);

        $this->assertStartedOnceNaming($result, $id, $fields['RelayState']);
    }

    /**
     * Two starts through the connection send, and store, distinct ids.
     *
     * @return void
     */
    public function testTwoStartsSendDistinctIds(): void
    {
        $connection = $this->saml();

        $this->startFlow($connection);
        $this->startFlow($connection);

        $ids = array_filter(AuthorizationRequest::query()->orderBy('id')->pluck('saml_request_id')->all(), is_string(...));

        self::assertCount(2, $ids);
        self::assertCount(2, array_unique($ids));

        foreach ($ids as $id) {
            self::assertMatchesRegularExpression('/^_[0-9a-f]{64}$/D', $id);
        }

        $this->assertEventSequence([AuthorizationRequestStarted::class, AuthorizationRequestStarted::class]);
    }

    /**
     * With expired metadata the start is refused with `metadata_expired`,
     * reporting one `FlowFailed` and storing nothing.
     *
     * @return void
     */
    public function testExpiredMetadataRefusesTheStart(): void
    {
        $connection = $this->saml(['metadata_url' => 'https://idp.example.test/metadata.xml', 'metadata_refresh' => true], [
            'metadata_fetched_at'  => $this->clock->now()->subHours(2),
            'metadata_valid_until' => $this->clock->now(),
        ]);

        $result = $this->startFlow($connection);

        self::assertTrue($result->isRefused());
        self::assertSame(FailureReason::METADATA_EXPIRED, $result->reason);
        self::assertNull($result->navigation);
        self::assertSame(0, AuthorizationRequest::query()->count());

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::METADATA_EXPIRED);
    }

    /**
     * Assert the start reported exactly `AuthorizationRequestStarted`, with its
     * reference and neither the request's id nor its `RelayState`.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $result
     * @param  string  $id
     * @param  string  $relayState
     * @return void
     */
    private function assertStartedOnceNaming(StartResult $result, string $id, string $relayState): void
    {
        $this->assertEventSequence([AuthorizationRequestStarted::class]);
        $this->assertNoFailure();

        $context = $this->recordedEvents()[0]->context()->toArray();
        $encoded = (string) json_encode($context);

        self::assertSame($result->reference?->value, $context['request_reference'] ?? null);
        self::assertSame('saml2', $context['protocol'] ?? null);
        self::assertStringNotContainsString($id, $encoded);
        self::assertStringNotContainsString($relayState, $encoded);
    }

    /**
     * Start a `sign_in` for `web` through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function startFlow(Connection $connection): StartResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $connection->id, Clients::browser());
    }

    /**
     * A usable SAML connection, trusting a signing certificate, with the
     * settings and attributes given.
     *
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(array $settings = [], array $attributes = []): Connection
    {
        $connection = $this->makeConnection([
            'protocol' => 'saml2',
            'enabled'  => true,
            'settings' => [...['idp_entity_id' => 'https://idp.example.com/entity', 'sso_url' => self::SSO_URL], ...$settings],
            ...$attributes,
        ]);

        $this->storeKey($connection, KeyUse::IDP_SIGNING, Certificates::distinct(0));

        return $connection;
    }

    /**
     * Store the service provider's current signing key for the connection, its
     * private half encrypted as the key service would.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function signingKey(Connection $connection): void
    {
        $this->storeKey($connection, KeyUse::SP_SIGNING, self::keys()[1], KeyState::CURRENT, app(SecretEncrypter::class)->encrypt(self::keys()[0]));
    }

    /**
     * Store a key or trusted certificate of the use for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  string  $certificate
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  ?string  $privateKey
     * @return void
     */
    private function storeKey(Connection $connection, KeyUse $use, string $certificate, ?KeyState $state = null, ?string $privateKey = null): void
    {
        $public  = openssl_pkey_get_public($certificate);
        $details = $public === false ? false : openssl_pkey_get_details($public);

        self::assertIsArray($details);

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => $use,
            'state'         => $state,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $certificate,
            'public_key'    => $details['key'],
            'private_key'   => $privateKey,
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();
    }

    /**
     * The service provider's signing key and certificate, made once.
     *
     * @return array{0: string, 1: string}
     */
    private static function keys(): array
    {
        return self::$spKeys ??= FakeSamlIdentityProvider::keyPair('sp.example.test');
    }

    /**
     * The `ID` of the `AuthnRequest` in the XML.
     *
     * @param  string  $xml
     * @return string
     */
    private static function requestIdOf(string $xml): string
    {
        $document = new \DOMDocument;

        self::assertTrue($document->loadXML($xml, LIBXML_NONET));

        $root = $document->documentElement;

        self::assertNotNull($root);
        self::assertSame([self::NS_SAMLP, 'AuthnRequest'], [$root->namespaceURI, $root->localName]);
        self::assertMatchesRegularExpression('/^_[0-9a-f]{64}$/D', $root->getAttribute('ID'));

        return $root->getAttribute('ID');
    }
}
