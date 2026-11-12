<?php

declare(strict_types = 1);

namespace Benchmarks\Protocols;

use Benchmarks\Support\BenchApplication;
use Carbon\CarbonImmutable;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\ParamProviders;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;

/**
 * `AssertionValidator::validate()` on valid and rejected SAML responses.
 *
 * Fixtures are built in `setUp`, so each revolution times validation only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[BeforeMethods('setUp')]
#[Iterations(5)]
#[ParamProviders('provideVersions')]
#[Revs(50)]
#[Warmup(1)]
final class SamlValidationBench
{
    /** @var string The request every response answers. */
    private const string REQUEST_ID = '_request-1';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Vq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var string The `RelayState` the browser posts. */
    private const string RELAY_STATE = 'relay';

    /** @var \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator The validator. */
    private AssertionValidator $validator; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the responses arrive for. */
    private Connection $connection; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options The connection's options. */
    private Saml2Options $options; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\ConsumedRequest The request the responses answer. */
    private ConsumedRequest $consumed; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\CompletionRequest A signed assertion, valid. */
    private CompletionRequest $validSigned; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\CompletionRequest An encrypted assertion, valid. */
    private CompletionRequest $validEncrypted; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\CompletionRequest An assertion signed by a key the connection does not trust. */
    private CompletionRequest $badSignature; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\CompletionRequest An assertion whose conditions have ended. */
    private CompletionRequest $expired; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\CompletionRequest An assertion for another service provider. */
    private CompletionRequest $wrongAudience; // @phpstan-ignore property.uninitialized

    /**
     * Store a connection trusting the provider and make every response once.
     *
     * @return void
     */
    public function setUp(): void
    {
        $app = BenchApplication::boot();
        $now = CarbonImmutable::parse(BenchApplication::NOW);
        $idp = new FakeSamlIdentityProvider;
        $sp  = FakeSamlIdentityProvider::keyPair('sp.example.test');

        $this->validator  = $app->make(AssertionValidator::class);
        $this->connection = BenchApplication::connection([
            'protocol' => 'saml2',
            'settings' => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
        ]);

        $this->store(KeyUse::IDP_SIGNING, null, $idp->certificate());
        $this->store(KeyUse::SP_ENCRYPTION, KeyState::CURRENT, $sp[1], $app->make(SecretEncrypter::class)->encrypt($sp[0]));

        $endpoints = $app->make(EndpointResolver::class)->endpoints($this->connection);
        $response  = $idp->response($endpoints->entityId, $endpoints->assertionConsumerService, $now)->inResponseTo(self::REQUEST_ID);

        $this->options        = Saml2Options::of($this->connection);
        $this->consumed       = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString(self::REFERENCE), $now->subMinute(), samlRequestId: self::REQUEST_ID);
        $this->validSigned    = $response->completionRequest(self::RELAY_STATE);
        $this->validEncrypted = $response->encryptedFor($sp[1])->completionRequest(self::RELAY_STATE);
        $this->badSignature   = $response->signedBy((new FakeSamlIdentityProvider)->signer())->completionRequest(self::RELAY_STATE);
        $this->expired        = $response->with(['not_before' => $now->subHours(2), 'not_on_or_after' => $now->subHour()])->completionRequest(self::RELAY_STATE);
        $this->wrongAudience  = $response->with(['audiences' => [['https://other.example.test']]])->completionRequest(self::RELAY_STATE);
    }

    /**
     * The versions of the packages these times depend on.
     *
     * @return array<string, array<string, string>>
     */
    public function provideVersions(): array
    {
        return BenchApplication::versions('simplesamlphp/saml2', 'simplesamlphp/xml-security', 'laravel/framework');
    }

    /**
     * Validate a valid signed assertion.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    public function benchValidSigned(): Completion
    {
        return $this->validate($this->validSigned);
    }

    /**
     * Validate a valid encrypted assertion, decrypting it with the stored key.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    public function benchValidEncrypted(): Completion
    {
        return $this->validate($this->validEncrypted);
    }

    /**
     * Reject an assertion signed by a key the connection does not trust.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    public function benchBadSignature(): Completion
    {
        return $this->validate($this->badSignature);
    }

    /**
     * Reject an assertion whose conditions have ended.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    public function benchExpired(): Completion
    {
        return $this->validate($this->expired);
    }

    /**
     * Reject an assertion for another service provider.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    public function benchWrongAudience(): Completion
    {
        return $this->validate($this->wrongAudience);
    }

    /**
     * What the validator answers for the request.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function validate(CompletionRequest $request): Completion
    {
        return $this->validator->validate($this->connection, $this->options, $request, $this->consumed);
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
    private function store(KeyUse $use, ?KeyState $state, string $certificate, #[\SensitiveParameter] ?string $privateKey = null): void
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
            'private_key'     => $privateKey,
            'fingerprint'     => (string) openssl_x509_fingerprint($certificate, 'sha256'),
            'made_current_at' => $state === null ? null : CarbonImmutable::parse(BenchApplication::NOW),
        ])->save();
    }
}
