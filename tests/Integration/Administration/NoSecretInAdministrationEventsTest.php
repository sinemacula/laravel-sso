<?php

declare(strict_types = 1);

namespace Tests\Integration\Administration;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyMadeCurrent;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsEventSequences;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Integration tests, on a real database, that no administration event carries a
 * secret (SSO-2.5, SSO-10.4): across creating an OIDC connection with its
 * client secret, rotating the secret, changing a setting, generating a key pair
 * and trusting a certificate, neither the serialised event nor its context's
 * record holds the client secret, the private key, any ciphertext stored for
 * either, or a setting's value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdministrationEvents::class)]
#[CoversClass(EventContexts::class)]
#[CoversClass(ConnectionService::class)]
#[CoversClass(KeyService::class)]
final class NoSecretInAdministrationEventsTest extends TestCase
{
    use RecordsEventSequences;

    /** @var string The tenant whose connections the helpers act on. */
    private const string TENANT = 'tenant-1';

    /** @var string The client secret the connection is created with. */
    private const string SECRET = 'the-client-secret-value';

    /** @var string The client secret it is rotated to. */
    private const string ROTATED_SECRET = 'the-rotated-client-secret';

    /** @var string The token endpoint the connection is created with: a setting value. */
    private const string TOKEN_ENDPOINT = 'https://idp.example.com/token';

    /** @var string The token endpoint it is changed to. */
    private const string CHANGED_TOKEN_ENDPOINT = 'https://login.example.net/oauth2/v2.0/token';

    /** @var array<string, string> The settings of a complete OIDC connection. */
    private const array OIDC = [
        'issuer'                 => 'https://idp.example.com',
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => self::TOKEN_ENDPOINT,
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
    ];

    /**
     * Bind a fixed clock and a freshness contract that answers `fresh`, turn
     * both protocols on, create the tables, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.oidc', true);

        $this->usePackageTables();
        $this->startRecordingEvents();
    }

    /**
     * No event of the changes, serialised as a queue would or as its context's
     * JSON record, holds a secret, a private key, a ciphertext or a setting
     * value.
     *
     * @return void
     */
    public function testNoEventHoldsASecretOrASettingValue(): void
    {
        $actor = new ActingIdentity('App\Models\User', '42');
        $oidc  = (string) $this->connections()->create(
            self::TENANT,
            'oidc',
            'Acme',
            Clients::browser(),
            self::OIDC + ['client_secret' => self::SECRET],
            actor: $actor,
        )->connection?->id;

        $secretCiphertexts = $this->secretCiphertexts($oidc);

        $this->connections()->update(self::TENANT, $oidc, ['settings' => ['client_secret' => self::ROTATED_SECRET]], Clients::browser(), $actor);
        $this->connections()->update(self::TENANT, $oidc, ['settings' => ['token_endpoint' => self::CHANGED_TOKEN_ENDPOINT]], Clients::browser(), $actor);

        $secretCiphertexts = [...$secretCiphertexts, ...$this->secretCiphertexts($oidc)];

        self::assertTrue($this->keys()->addNext(self::TENANT, $oidc, KeyUse::CLIENT_ASSERTION, Clients::browser(), KeyType::EC, $actor)->isSucceeded());

        $saml = (string) $this->connections()->create(
            self::TENANT,
            'saml2',
            'Acme SAML',
            Clients::browser(),
            ['idp_entity_id' => 'https://idp.example.com/entity', 'sso_url' => 'https://idp.example.com/sso'],
            actor: $actor,
        )->connection?->id;

        self::assertTrue($this->keys()->trustCertificate(self::TENANT, $saml, Certificates::distinct(60), Clients::browser(), $actor)->isSucceeded());

        $this->assertEventSequence([
            ConnectionCreated::class,
            ConnectionUpdated::class,
            ConnectionUpdated::class,
            KeyAdded::class,
            KeyMadeCurrent::class,
            ConnectionCreated::class,
            KeyAdded::class,
        ]);

        $forbidden = [
            'the client secret'          => [self::SECRET],
            'the rotated client secret'  => [self::ROTATED_SECRET],
            'a secret ciphertext'        => $secretCiphertexts,
            'a private key ciphertext'   => $this->privateKeyCiphertexts(),
            'the private key'            => $this->privateKeys(),
            'the token endpoint'         => [self::TOKEN_ENDPOINT],
            'the changed token endpoint' => [self::CHANGED_TOKEN_ENDPOINT],
        ];

        foreach ($forbidden as $what => $values) {
            self::assertNotSame([], $values, sprintf('There is no %s to look for.', $what));
        }

        foreach ($this->recordedEvents() as $event) {

            $serialized = serialize($event);
            $record     = json_encode($event->context()->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

            foreach ($forbidden as $what => $values) {
                foreach ($values as $value) {
                    self::assertStringNotContainsString($value, $serialized, sprintf('%s holds %s.', $event::class, $what));
                    self::assertStringNotContainsString($value, $record, sprintf('The context of %s holds %s.', $event::class, $what));
                }
            }
        }
    }

    /**
     * The ciphertext of each secret the connection stores now.
     *
     * @param  string  $connectionId
     * @return list<string>
     */
    private function secretCiphertexts(string $connectionId): array
    {
        $stored = DB::connection(StorageConnection::name())->table(StorageConnection::table('connections.table'))->where('id', $connectionId)->value('secrets');

        self::assertIsString($stored);

        $secrets = json_decode($stored, true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($secrets);

        return self::strings($secrets);
    }

    /**
     * The ciphertext of each private key stored.
     *
     * @return list<string>
     */
    private function privateKeyCiphertexts(): array
    {
        return self::strings(DB::connection(StorageConnection::name())->table(StorageConnection::table('keys.table'))->whereNotNull('private_key')->pluck('private_key')->all());
    }

    /**
     * The strings among the values, in order.
     *
     * @param  array<array-key, mixed>  $values
     * @return list<string>
     */
    private static function strings(array $values): array
    {
        return array_values(array_filter($values, is_string(...)));
    }

    /**
     * Each private key stored, decrypted: the PEM, and each full line of its
     * body.
     *
     * @return list<string>
     */
    private function privateKeys(): array
    {
        /** @var \SineMacula\Laravel\Sso\Contracts\SecretEncrypter $encrypter */
        $encrypter = $this->app?->make(SecretEncrypter::class);
        $values    = [];

        foreach ($this->privateKeyCiphertexts() as $ciphertext) {

            $pem = $encrypter->decrypt($ciphertext);

            self::assertStringContainsString('PRIVATE KEY', $pem);

            $values[] = $pem;

            foreach (explode("\n", $pem) as $line) {

                if (strlen($line) < 32 || str_starts_with($line, '-----')) {
                    continue;
                }

                $values[] = $line;
            }
        }

        return $values;
    }

    /**
     * The connection helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function connections(): ConnectionService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ConnectionService::class);
    }

    /**
     * The key helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyService
     */
    private function keys(): KeyService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(KeyService::class);
    }
}
