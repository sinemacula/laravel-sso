<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\AuthorizationRequests;
use SineMacula\Laravel\Sso\Protocols\Oidc\CallbackCompletion;
use SineMacula\Laravel\Sso\Protocols\Oidc\CallbackCorrelator;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Protocols\Oidc\RelyingPartyDescription;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Feature tests for the `oidc` driver's own decisions (SSO-2.2, SSO-2.4,
 * SSO-2.8, SSO-5.4): it is built from the container and reads OIDC settings; a
 * connection is complete only with complete settings and its client
 * authentication's credential (a client secret, or a current `private_key_jwt`
 * key); a start and a completion are refused with `metadata_expired` once what
 * a refresh applied expires, its JWKS included, and go on to their collaborator
 * until then; and the correlation and the description are its collaborators'.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OidcDriver::class)]
#[CoversClass(AuthorizationRequests::class)]
#[CoversClass(CallbackCorrelator::class)]
#[CoversClass(CallbackCompletion::class)]
#[CoversClass(RelyingPartyDescription::class)]
final class OidcDriverTest extends TestCase
{
    use UsesConnections;

    /** @var array<string, string> Complete settings. */
    private const array SETTINGS = [
        'issuer'                 => 'https://op.example.test',
        'authorization_endpoint' => 'https://op.example.test/authorize',
        'token_endpoint'         => 'https://op.example.test/token',
        'jwks_uri'               => 'https://op.example.test/jwks',
        'client_id'              => 'client-1',
    ];

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /**
     * Bind a fixed clock, configure OIDC and the endpoints, and create the
     * tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');

        $this->usePackageTables();
    }

    /**
     * The manager builds the driver from the container, and the driver reads
     * OIDC settings.
     *
     * @return void
     */
    public function testIsBuiltFromTheContainerAndReadsOidcSettings(): void
    {
        $driver = app(ProtocolManager::class)->protocol(OidcDriver::NAME);

        self::assertInstanceOf(OidcDriver::class, $driver);
        self::assertSame('oidc', OidcDriver::NAME);
        self::assertInstanceOf(OidcSettings::class, $driver->settings(['client_id' => 'client-1']));
        self::assertSame('client-1', $driver->settings(['client_id' => 'client-1'])->toArray()['client_id']);
    }

    /**
     * Rows of `[settings, secret, key, complete]`: a connection's settings,
     * whether its client secret is set, the state of its client assertion key
     * if it has one, and whether it is complete.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool, 2: ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState, 3: bool}>
     */
    public static function provideCompleteness(): iterable
    {
        $post = [...self::SETTINGS, 'client_authentication' => 'client_secret_post'];
        $jwt  = [...self::SETTINGS, 'client_authentication' => 'private_key_jwt'];

        yield from [
            'basic with a secret'                => [self::SETTINGS, true, null, true],
            'basic without a secret'             => [self::SETTINGS, false, null, false],
            'basic with only a key'              => [self::SETTINGS, false, KeyState::CURRENT, false],
            'post with a secret'                 => [$post, true, null, true],
            'post without a secret'              => [$post, false, null, false],
            'private key jwt with a current key' => [$jwt, false, KeyState::CURRENT, true],
            'private key jwt with a next key'    => [$jwt, false, KeyState::NEXT, false],
            'private key jwt with only a secret' => [$jwt, true, null, false],
            'incomplete settings'                => [array_diff_key(self::SETTINGS, ['jwks_uri' => true]), true, null, false],
            'invalid settings'                   => [[...self::SETTINGS, 'issuer' => 'http://op.example.test'], true, null, false],
            'userinfo without its endpoint'      => [[...self::SETTINGS, 'fetch_userinfo' => true], true, null, false],
        ];
    }

    /**
     * A connection is complete only with complete settings and its client
     * authentication's credential, read from the row however it is given.
     *
     * @param  array<string, mixed>  $settings
     * @param  bool  $secret
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState  $key
     * @param  bool  $complete
     * @return void
     */
    #[DataProvider('provideCompleteness')]
    public function testIsCompleteOnlyWithItsCredential(array $settings, bool $secret, ?KeyState $key, bool $complete): void
    {
        $connection = $this->oidc($settings, $secret);

        if ($key !== null) {
            $this->clientKey($connection, $key);
        }

        self::assertSame($complete, $this->driver()->isComplete($connection));
        self::assertSame($complete, $this->driver()->isComplete(new IdentifiedConnection($connection->id, settings: $settings)));
    }

    /**
     * A connection given through its contract and gone has no secret.
     *
     * @return void
     */
    public function testAConnectionThatIsGoneHasNoSecret(): void
    {
        self::assertFalse($this->driver()->isComplete(new IdentifiedConnection('01jbgoneconnection00000000', settings: self::SETTINGS)));
    }

    /**
     * A start and a completion are refused with `metadata_expired` once the
     * discovery document or the JWKS expires, and go on to their collaborator
     * until then: the start navigates, and the completion reads the provider's
     * error, with no token request.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFlowIsRefusedOnceTheRefreshExpires(): void
    {
        $now        = $this->clock->now();
        $connection = $this->oidc(self::SETTINGS, true, ['metadata_fetched_at' => $now, 'jwks_fetched_at' => $now->subDay()]);

        self::assertSame([null, FailureReason::PROVIDER_ERROR], $this->answers($connection));

        $this->clock->advance(29 * 86400 - 1);

        self::assertSame([null, FailureReason::PROVIDER_ERROR], $this->answers($connection));

        $this->clock->advance(1);

        self::assertSame([FailureReason::METADATA_EXPIRED, FailureReason::METADATA_EXPIRED], $this->answers($connection));
    }

    /**
     * The correlator reads the callback's `state`, refusing one that is not the
     * package's, and the description answers its document.
     *
     * @return void
     */
    public function testTheCorrelationAndTheDescriptionAreTheCollaborators(): void
    {
        $connection  = $this->oidc(self::SETTINGS, true);
        $state       = str_repeat('A', 43);
        $correlation = $this->driver()->correlate($connection, new CompletionRequest('GET', 'code=a&state=' . $state, []));
        $description = $this->driver()->describe($connection);

        self::assertTrue($this->driver()->correlate($connection, new CompletionRequest('GET', 'code=a&state=b', []))->isUncorrelated());
        self::assertSame([false, $state], [$correlation->isUncorrelated(), $correlation->state?->reveal()]);
        self::assertSame([true, null, 'application/json'], [$description->isAvailable(), $description->reason, $description->contentType]);
    }

    /**
     * The reasons a start and a completion through the connection were refused
     * with, the callback naming the provider's error so that no token request
     * is sent.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return list<?\SineMacula\Laravel\Sso\Events\Enums\FailureReason>
     */
    private function answers(Connection $connection): array
    {
        $driver    = $this->driver();
        $reference = RequestReference::fromString('Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456');
        $request   = new StartRequest(Purpose::SIGN_IN, 'web', $reference, new Secret('state'), new Secret('nonce'), new Secret('verifier'));
        $start     = $driver->start($connection, $request);
        $consumed  = new ConsumedRequest(Purpose::SIGN_IN, 'web', $reference, CarbonImmutable::now());
        $complete  = $driver->complete($connection, new CompletionRequest('GET', 'error=access_denied&state=b', []), $consumed);

        return [$start->reason, $complete->reason];
    }

    /**
     * The driver, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver
     */
    private function driver(): OidcDriver
    {
        return app(OidcDriver::class);
    }

    /**
     * An OIDC connection with the settings and attributes given, and its client
     * secret set when asked.
     *
     * @param  array<string, mixed>  $settings
     * @param  bool  $secret
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function oidc(array $settings, bool $secret, array $attributes = []): Connection
    {
        $secrets = $secret ? app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret('shh')]) : null;

        return $this->makeConnection(['protocol' => 'oidc', 'enabled' => true, 'settings' => $settings, 'secrets' => $secrets, ...$attributes]);
    }

    /**
     * Store a client assertion key of the state for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @return void
     */
    private function clientKey(Connection $connection, KeyState $state): void
    {
        $certificate = Certificates::ecP256();
        $public      = openssl_pkey_get_public($certificate);
        $details     = $public === false ? false : openssl_pkey_get_details($public);

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::CLIENT_ASSERTION,
            'state'         => $state,
            'key_type'      => KeyType::EC,
            'key_bits'      => 256,
            'certificate'   => $certificate,
            'public_key'    => is_array($details) ? $details['key'] : '',
            'private_key'   => 'ciphertext',
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();
    }
}
