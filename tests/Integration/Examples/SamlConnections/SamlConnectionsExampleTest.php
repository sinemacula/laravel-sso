<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SamlConnections;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/saml-connections.md` (SSO-2.3, SSO-2.6, SSO-2.7,
 * SSO-2.11, SSO-12.5), on the shared example harness, with the application's
 * own tenant: the administration screen creates the tenant's SAML connection
 * disabled and not yet usable, generates its signing and encryption keys, each
 * made current at once, trusts the identity provider's signing certificate and
 * enables it, after which the connection is usable and a person links through
 * it with an assertion the provider encrypted for the published encryption
 * certificate. A connection enabled before it trusts a certificate is enabled
 * but never used, so a flow through it never starts; and an elliptic curve key
 * or certificate is refused when it is configured, writing nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionService::class)]
#[CoversClass(ConnectionResult::class)]
#[CoversClass(KeyService::class)]
#[CoversClass(KeyResult::class)]
final class SamlConnectionsExampleTest extends ExampleTestCase
{
    /** @var string The identity provider's entity id the guide's connection names. */
    private const string IDP_ENTITY_ID = 'https://sts.windows.net/0000-1111/';

    /** @var \Tests\Integration\Examples\SamlConnections\Tenant The tenant whose connection is set up. */
    private Tenant $tenant;

    /** @var \SineMacula\Laravel\Sso\Administration\ActingIdentity The administrator setting it up. */
    private ActingIdentity $actor;

    /**
     * Make the tenant and the administrator acting for it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->tenant = new Tenant(self::TENANT);
        $this->actor  = new ActingIdentity('App\Models\User', '42');
    }

    /**
     * Each step in the guide's order: the connection is created disabled with
     * the settings given, gets a current signing key and a current encryption
     * key, trusts the provider's certificate, and is enabled, after which it is
     * usable; the key changes ask `sso.keys.rotate` and the trust change asks
     * `sso.connection.trust`. A person then links through it, the provider
     * encrypting its assertion for the connection's encryption certificate.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testSettingUpAConnectionFromStartToFinish(): void
    {
        $idp          = new FakeSamlIdentityProvider(self::IDP_ENTITY_ID);
        $created      = $this->created();
        $connectionId = (string) $created->connection?->id;

        self::assertSame(ConnectionStatus::CREATED, $created->status);
        self::assertSame([false, false], [$created->connection?->enabled, $created->connection?->usable]);
        self::assertEquals([
            'idp_entity_id'  => self::IDP_ENTITY_ID,
            'sso_url'        => 'https://login.microsoftonline.com/0000-1111/saml2',
            'sso_binding'    => 'http_redirect',
            'name_id_format' => 'persistent',
        ], array_intersect_key($created->connection->settings ?? [], array_flip(['idp_entity_id', 'sso_url', 'sso_binding', 'name_id_format'])));

        self::assertSame([['sp_signing', 'current', 'rsa'], ['sp_encryption', 'current', 'rsa']], self::listed($this->perform('keys', ['connection_id' => $connectionId])));
        $this->freshness->assertAsked(FreshnessOperation::KEYS_ROTATE);

        $trusted = $this->perform('trust', ['keys' => app(KeyService::class), 'connection_id' => $connectionId, 'certificate' => $idp->certificate()]);

        self::assertSame([['sp_signing', 'current', 'rsa'], ['sp_encryption', 'current', 'rsa'], ['idp_signing', null, 'rsa']], self::listed($trusted));
        $this->freshness->assertAsked(FreshnessOperation::CONNECTION_TRUST);

        $enabled = $this->enable($connectionId);

        self::assertSame(ConnectionStatus::ENABLED, $enabled->status);
        self::assertSame([true, true], [$enabled->connection?->enabled, app(ConnectionService::class)->get(self::TENANT, $connectionId)?->usable]);

        $this->assertALinkCompletesEncrypted($idp, $connectionId, self::encryptionCertificate($trusted));
    }

    /**
     * Enabling does not check that the connection is complete: one that trusts
     * no certificate is enabled, but is not usable, and a flow through it is
     * refused as `connection_unavailable`.
     *
     * @return void
     */
    public function testAnIncompleteConnectionIsEnabledButNeverUsed(): void
    {
        $connectionId = (string) $this->created()->connection?->id;
        $enabled      = $this->enable($connectionId);

        self::assertSame(ConnectionStatus::ENABLED, $enabled->status);
        self::assertSame([true, false], [$enabled->connection?->enabled, app(ConnectionService::class)->get(self::TENANT, $connectionId)?->usable]);

        $start = $this->startFlow(Purpose::LINK, $connectionId, new IdentityReference('App\Models\User', 'person-1'));

        self::assertTrue($start->isRefused());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $start->reason);
    }

    /**
     * SAML is RSA only: an elliptic curve key for either of the service
     * provider's uses is invalid as `key_type` `not_allowed`, and an elliptic
     * curve certificate trusted as the provider's signing certificate is
     * invalid as `certificate` `unsupported`. None is stored.
     *
     * @return void
     */
    public function testAnEllipticCurveKeyOrCertificateIsRefused(): void
    {
        $connectionId = (string) $this->created()->connection?->id;
        $keys         = app(KeyService::class);

        foreach ([KeyUse::SP_SIGNING, KeyUse::SP_ENCRYPTION] as $use) {
            self::assertSame([['key_type', 'not_allowed']], self::violationsOf($keys->addNext(self::TENANT, $connectionId, $use, KeyType::EC, $this->actor)));
        }

        $trusted = $keys->trustCertificate(self::TENANT, $connectionId, self::ellipticCurveCertificate(), $this->actor);

        self::assertSame([['certificate', 'unsupported']], self::violationsOf($trusted));
        self::assertSame([], $keys->keys(self::TENANT, $connectionId));
    }

    /**
     * A person links through the connection, the provider encrypting its
     * assertion for the certificate: the code is redeemed for the person.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $idp
     * @param  string  $connectionId
     * @param  string  $certificate
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function assertALinkCompletesEncrypted(FakeSamlIdentityProvider $idp, string $connectionId, string $certificate): void
    {
        $person    = new IdentityReference('App\Models\User', 'person-1');
        $start     = $this->startFlow(Purpose::LINK, $connectionId, $person);
        $encrypted = static fn (FakeSamlResponse $response): FakeSamlResponse => $response->encryptedFor($certificate);
        $linked    = $this->redeemLink($connectionId, $this->respondAtProvider($idp, $connectionId, $start, $encrypted), $start, $person);

        self::assertTrue($linked->isRedeemed());
        self::assertEquals($person, $linked->identity);
    }

    /**
     * Run the create step as the administrator, and answer its result.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     */
    private function created(): ConnectionResult
    {
        $result = $this->perform('create');

        self::assertInstanceOf(ConnectionResult::class, $result);

        return $result;
    }

    /**
     * Run the enable step for the connection as the administrator, and answer
     * its result.
     *
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     */
    private function enable(string $connectionId): ConnectionResult
    {
        $result = $this->perform('enable', ['connection_id' => $connectionId]);

        self::assertInstanceOf(ConnectionResult::class, $result);

        return $result;
    }

    /**
     * Run a step of the administration screen with the tenant, the
     * administrator and the rest of its input, and answer what it answers.
     *
     * @param  string  $step
     * @param  array<string, mixed>  $input
     * @return mixed
     */
    private function perform(string $step, array $input = []): mixed
    {
        return self::atStep($step, ['tenant' => $this->tenant, 'actor' => $this->actor, ...$input]);
    }

    /**
     * The step's script, given its input.
     *
     * @param  string  $step
     * @param  array<string, mixed>  $input
     * @return mixed
     */
    private static function atStep(string $step, array $input): mixed
    {
        return require __DIR__ . "/admin/{$step}.php";
    }

    /**
     * The use, state and key type of each key the listing holds, in order.
     *
     * @param  mixed  $listed
     * @return list<array{0: string, 1: ?string, 2: string}>
     */
    private static function listed(mixed $listed): array
    {
        self::assertIsArray($listed);

        return array_values(array_map(static fn (KeySummary $key): array => [$key->use->value, $key->state?->value, $key->type->value], $listed));
    }

    /**
     * The PEM certificate of the connection's current encryption key, which its
     * metadata publishes for the provider to encrypt for.
     *
     * @param  mixed  $listed
     * @return string
     */
    private static function encryptionCertificate(mixed $listed): string
    {
        self::assertIsArray($listed);

        $encryption = array_values(array_filter($listed, static fn (KeySummary $key): bool => $key->use === KeyUse::SP_ENCRYPTION));

        self::assertCount(1, $encryption);
        self::assertInstanceOf(KeySummary::class, $encryption[0]);

        return (string) $encryption[0]->key->certificate;
    }

    /**
     * Each violation of the result, as its setting and code.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyResult  $result
     * @return list<array{0: string, 1: string}>
     */
    private static function violationsOf(KeyResult $result): array
    {
        self::assertTrue($result->isInvalid());

        return array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $result->violations);
    }

    /**
     * A self-signed P-256 certificate, such as an identity provider that signs
     * only with ECDSA would give.
     *
     * @return string
     */
    private static function ellipticCurveCertificate(): string
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $key);

        $csr = openssl_csr_new(['commonName' => 'idp.example.test'], $key, ['digest_alg' => 'sha256']);

        self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);

        $certificate = openssl_csr_sign($csr, null, $key, 365, ['digest_alg' => 'sha256']);

        self::assertInstanceOf(\OpenSSLCertificate::class, $certificate);
        self::assertTrue(openssl_x509_export($certificate, $pem));

        return $pem;
    }
}
