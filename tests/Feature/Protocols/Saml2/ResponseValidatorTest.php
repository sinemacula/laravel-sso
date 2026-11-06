<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Saml2\ResponseValidator;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the solicited response path (SSO-6.2 to SSO-6.10): the
 * validator holds a response to every rule against the request consumed for it,
 * answering its claims and replay record, or why it is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResponseValidator::class)]
final class ResponseValidatorTest extends TestCase
{
    use UsesConnections;

    /** @var string The request the responses answer. */
    private const string REQUEST_ID = '_request-1';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the responses arrive for. */
    private Connection $connection;

    /**
     * Bind a fixed clock, configure the endpoints, and create the tables and a
     * connection that trusts the identity provider.
     *
     * @return void
     *
     * @throws \LogicException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        config()->set('sso.endpoints.base_url', 'https://sp.example.test');

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'protocol' => 'saml2',
            'enabled'  => true,
            'settings' => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
        ]);

        $certificate = self::idp()->certificate();
        $details     = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A certificate has a public key.'));

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
     * A response answering the consumed request is verified, with its
     * assertion's replay record.
     *
     * @return void
     */
    public function testVerifiesAResponseAgainstTheConsumedRequest(): void
    {
        $completion = $this->complete($this->response()->with(['assertion_id' => '_assertion-9']), self::REQUEST_ID);

        self::assertTrue($completion->isVerified());
        self::assertSame('v1|7:name_id|52:' . FakeSamlResponse::PERSISTENT . '|-|-|5:alice', $completion->claims?->subject);
        self::assertSame('saml_assertion', $completion->replay?->namespace);
    }

    /**
     * A response answering another request than the one consumed is refused.
     *
     * @return void
     */
    public function testRefusesAResponseToAnotherRequest(): void
    {
        $completion = $this->complete($this->response(), '_request-2');

        self::assertSame([FailureReason::REQUEST_MISMATCH, null, null], [$completion->reason, $completion->claims, $completion->replay]);
    }

    /**
     * Validate the response against a request consumed with the SAML request
     * id.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @param  string  $requestId
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function complete(FakeSamlResponse $response, string $requestId): Completion
    {
        $reference = RequestReference::fromString('Wq8tVv3w0kLmNoPqRsTuVwXyZ0123456');
        $consumed  = new ConsumedRequest(Purpose::SIGN_IN, 'web', $reference, $this->clockNow()->subMinute(), samlRequestId: $requestId);

        return app(ResponseValidator::class)->complete($this->connection, Saml2Options::of($this->connection), $response->completionRequest('relay'), $consumed);
    }

    /**
     * A valid response from the identity provider, made now, answering the
     * request.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function response(): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->clockNow())->inResponseTo(self::REQUEST_ID);
    }

    /**
     * The package clock's now.
     *
     * @return \Carbon\CarbonImmutable
     */
    private function clockNow(): CarbonImmutable
    {
        return app(Clock::class)->now();
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
