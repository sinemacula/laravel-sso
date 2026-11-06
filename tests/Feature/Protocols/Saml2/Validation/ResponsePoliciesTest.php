<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ResponsePolicies;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\Fixtures\Secrets\CountingSecretEncrypter;
use Tests\TestCase;

/**
 * Feature tests for what the SAML adapter holds a connection's response to
 * (SSO-2.6, SSO-6.2, SSO-6.7, SSO-6.8): the identity provider signing
 * certificates the connection trusts now, oldest first, and no anchor or other
 * connection's; the algorithms its settings allow, AES-CBC only when listed;
 * and its decryption keys, current then retiring within their overlap, read and
 * decrypted only when the adapter asks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResponsePolicies::class)]
final class ResponsePoliciesTest extends TestCase
{
    use UsesConnections;

    /** @var string AES-128-CBC. */
    private const string AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Secrets\CountingSecretEncrypter The encrypter, counting decryptions. */
    private CountingSecretEncrypter $encrypter;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection whose policy is built. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\Connection Another connection, of the same tenant. */
    private Connection $other;

    /** @var int How many own keys the test has stored, so each has its own certificate. */
    private int $ownKeys = 0;

    /**
     * Bind a fixed clock and a counting encrypter, and create the tables and
     * two connections.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock     = new FixedClock('2026-11-01T09:30:00Z');
        $this->encrypter = new CountingSecretEncrypter(app(SecretEncrypter::class));

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(SecretEncrypter::class, $this->encrypter);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2', 'enabled' => true, 'settings' => ['idp_entity_id' => 'https://idp.example.test/saml']]);
        $this->other      = $this->makeConnection(['protocol' => 'saml2', 'enabled' => true]);
    }

    /**
     * The trusted certificates are the connection's identity provider signing
     * certificates, oldest first; a metadata signing anchor and another
     * connection's certificate are not among them.
     *
     * @return void
     */
    public function testTrustsTheConnectionsSigningCertificatesOldestFirst(): void
    {
        $first = Certificates::distinct(1);
        $later = Certificates::distinct(2);

        $this->trust($this->connection, $first, KeyUse::IDP_SIGNING);
        $this->clock->advance(60);
        $this->trust($this->connection, Certificates::distinct(3), KeyUse::METADATA_SIGNING);
        $this->trust($this->other, Certificates::distinct(4), KeyUse::IDP_SIGNING);
        $this->clock->advance(60);
        $this->trust($this->connection, $later, KeyUse::IDP_SIGNING);

        self::assertSame([self::canonical($first), self::canonical($later)], $this->policy()->trustedCertificates);
        self::assertSame([self::canonical(Certificates::distinct(4))], $this->policy([], $this->other)->trustedCertificates);
    }

    /**
     * The algorithms are the connection's: every signature algorithm and the
     * default key transport and data encryption ones, and AES-CBC once listed.
     *
     * @return void
     */
    public function testAllowsTheConnectionsAlgorithms(): void
    {
        $default = $this->policy();
        $listed  = $this->policy(['encryption_algorithms' => [...Saml2Settings::KEY_TRANSPORT_ALGORITHMS, self::AES128_CBC]]);
        $narrow  = $this->policy(['signature_algorithms' => ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha512']]);

        self::assertSame(Saml2Settings::SIGNATURE_ALGORITHMS, $default->signatureAlgorithms);
        self::assertSame(Saml2Settings::KEY_TRANSPORT_ALGORITHMS, $default->keyTransportAlgorithms);
        self::assertSame(Saml2Settings::DATA_ENCRYPTION_ALGORITHMS, $default->dataEncryptionAlgorithms);
        self::assertSame([self::AES128_CBC], $listed->dataEncryptionAlgorithms);
        self::assertSame(['http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'], $narrow->signatureAlgorithms);
    }

    /**
     * The decryption keys are read and decrypted only when asked for: the
     * current key, then each retiring one still within its overlap, newest
     * first; an expired one, a signing key and another connection's are not
     * among them.
     *
     * @return void
     */
    public function testDecryptsTheDecryptionKeysOnlyWhenAsked(): void
    {
        $this->ownKey($this->connection, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, 'older', self::retiring('08:00:00', '10:30:00'));
        $this->ownKey($this->connection, KeyUse::SP_ENCRYPTION, KeyState::CURRENT, 'current', ['made_current_at' => self::at('09:30:00')]);
        $this->ownKey($this->connection, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, 'newer', self::retiring('09:00:00', '10:00:00'));
        $this->ownKey($this->connection, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, 'expired', self::retiring('07:00:00', '09:30:00'));
        $this->ownKey($this->connection, KeyUse::SP_SIGNING, KeyState::CURRENT, 'signing', ['made_current_at' => self::at('09:00:00')]);
        $this->ownKey($this->other, KeyUse::SP_ENCRYPTION, KeyState::CURRENT, 'other', ['made_current_at' => self::at('09:00:00')]);

        $policy = $this->policy();

        self::assertSame(0, $this->encrypter->decryptions);

        $keys = $policy->decryptionKeys();

        self::assertSame(['current', 'newer', 'older'], array_map(static fn (Secret $key): string => $key->reveal(), $keys));
        self::assertSame(3, $this->encrypter->decryptions);
    }

    /**
     * The policy of the connection, with the settings given.
     *
     * @param  array<string, mixed>  $settings
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy
     */
    private function policy(array $settings = [], ?Connection $connection = null): ResponsePolicy
    {
        $connection ??= $this->connection;

        $connection->forceFill(['settings' => [...$connection->settings ?? [], ...$settings]]);

        return app(ResponsePolicies::class)->policy($connection, Saml2Options::of($connection));
    }

    /**
     * Trust the certificate for the use on the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $certificate
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return void
     *
     * @throws \LogicException
     */
    private function trust(Connection $connection, string $certificate, KeyUse $use): void
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A fixture certificate has a public key.'));

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => $use,
            'state'         => null,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $certificate,
            'public_key'    => is_array($details) ? $details['key'] : '',
            'private_key'   => null,
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();
    }

    /**
     * Store one of the connection's own keys, under a certificate of its own,
     * its private half the text given, encrypted.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  string  $private
     * @param  array<string, mixed>  $attributes
     * @return void
     *
     * @throws \LogicException
     */
    private function ownKey(Connection $connection, KeyUse $use, KeyState $state, string $private, array $attributes): void
    {
        $certificate = Certificates::distinct(10 + $this->ownKeys++);
        $details     = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A fixture certificate has a public key.'));

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => $use,
            'state'         => $state,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $certificate,
            'public_key'    => is_array($details) ? $details['key'] : '',
            'private_key'   => $this->encrypter->encrypt($private),
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
            ...$attributes,
        ])->save();
    }

    /**
     * The certificate as the key ring answers it: exported by OpenSSL.
     *
     * @param  string  $certificate
     * @return string
     */
    private static function canonical(string $certificate): string
    {
        $read = openssl_x509_read($certificate);

        return $read !== false && openssl_x509_export($read, $exported) ? $exported : '';
    }

    /**
     * The attributes of a key made current at the one time and retiring until
     * the other, on the clock's day.
     *
     * @param  string  $madeCurrent
     * @param  string  $retiringUntil
     * @return array<string, \Carbon\CarbonImmutable>
     */
    private static function retiring(string $madeCurrent, string $retiringUntil): array
    {
        return ['made_current_at' => self::at($madeCurrent), 'retiring_until' => self::at($retiringUntil)];
    }

    /**
     * The instant at the time on the clock's day.
     *
     * @param  string  $time
     * @return \Carbon\CarbonImmutable
     */
    private static function at(string $time): CarbonImmutable
    {
        return CarbonImmutable::parse('2026-11-01T' . $time . 'Z');
    }
}
