<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Saml2\ResponseCorrelator;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Links\ExampleLinks;

/**
 * Query budgets for completing a SAML sign-in (SSO-5.6, SSO-6.6, SSO-11.3,
 * SSO-11.5), each measured once the IP address's and the connection's counters
 * exist, so every completion first costs their two updates. Beside a completion
 * through any driver (`CompletionQueryBudgetTest`), the SAML driver reads the
 * connection's trusted certificates to judge it complete before it validates,
 * again for the adapter's policy, and again under the lock, and records the
 * assertion's id in the locked transaction:
 *
 * - a signed assertion is eight reads and six writes;
 * - an encrypted one adds the decryption keys' read and the private key's;
 * - a response refused before it is verified records nothing and takes no
 *   lock that judges the connection again: seven reads and five writes;
 * - a post with no response is the connection's read alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(ResponseCorrelator::class)]
#[CoversClass(AssertionValidator::class)]
final class SamlCompletionQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?array{0: string, 1: string} The service provider's encryption key and certificate, made once. */
    private static ?array $spKeys = null;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable SAML connection. */
    private Connection $connection;

    /**
     * Bind the recording issuer, a linker and a request from an IP address,
     * configure SAML, the endpoints and the application, make a usable
     * connection that maps the email and has an encryption key, and create the
     * counters.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(HandoffIssuer::class, new RecordingHandoffIssuer);
        $this->app?->instance(Linker::class, new readonly class implements Linker {
            /**
             * One identity for every result.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result): LinkResolution
            {
                unset($result);

                return ExampleLinks::resolution(new IdentityReference('App\Models\User', '42'));
            }
        });
        $this->app?->instance('request', Request::create('/auth/sso/connections/x/assertions', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.saml2', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $this->connection = $this->makeConnection([
            'protocol'          => 'saml2',
            'enabled'           => true,
            'settings'          => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
            'attribute_mapping' => ['email' => 'email'],
        ]);

        $this->key(KeyUse::IDP_SIGNING, null, self::idp()->certificate(), null);
        $this->key(KeyUse::SP_ENCRYPTION, KeyState::CURRENT, self::spKeys()[1], self::spKeys()[0]);

        $this->complete(new CompletionRequest('POST', '', []));
    }

    /**
     * A completion of a signed assertion is eight reads and six writes.
     *
     * @return void
     */
    public function testACompletionIsEightReadsAndSixWrites(): void
    {
        $this->request('_request-1', 'relay-1');

        $result = $this->assertQueryBudget(8, 6, fn (): CompletionResult => $this->complete($this->response('_request-1')->completionRequest('relay-1')));

        self::assertTrue($result->isCompleted());
    }

    /**
     * A completion of an encrypted assertion adds the two reads of its
     * decryption key: ten reads and six writes.
     *
     * @return void
     */
    public function testAnEncryptedAssertionAddsTheReadsOfItsKey(): void
    {
        $this->request('_request-2', 'relay-2');

        $response = $this->response('_request-2')->encryptedFor(self::spKeys()[1]);
        $result   = $this->assertQueryBudget(10, 6, fn (): CompletionResult => $this->complete($response->completionRequest('relay-2')));

        self::assertTrue($result->isCompleted());
    }

    /**
     * A response refused before it is verified is seven reads and five writes,
     * and a post with no response is the connection's read alone.
     *
     * @return void
     */
    public function testARefusalRecordsNothing(): void
    {
        $this->request('_request-3', 'relay-3');

        $unsigned = $this->response('_request-3')->signed(false, false)->completionRequest('relay-3');
        $refused  = $this->assertQueryBudget(7, 5, fn (): CompletionResult => $this->complete($unsigned));
        $empty    = $this->assertQueryBudget(1, 2, fn (): CompletionResult => $this->complete(new CompletionRequest('POST', '', [])));

        self::assertSame([FailureReason::SIGNATURE_INVALID, FailureReason::REQUEST_UNKNOWN], [$refused->reason, $empty->reason]);
    }

    /**
     * Complete at the connection's assertion consumer service.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(CompletionRequest $request): CompletionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(CompletionService::class)->assertionConsumerService($this->connection->id, $request);
    }

    /**
     * Store a request through the connection with the `AuthnRequest` id and the
     * `RelayState`.
     *
     * @param  string  $requestId
     * @param  string  $relayState
     * @return void
     */
    private function request(string $requestId, string $relayState): void
    {
        $this->makeAuthorizationRequest($this->connection, ['saml_request_id' => $requestId, 'state_digest' => hash('sha256', $relayState)]);
    }

    /**
     * A valid response from the trusted identity provider, made now, answering
     * the request.
     *
     * @param  string  $requestId
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function response(string $requestId): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->clock->now())->inResponseTo($requestId);
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
}
