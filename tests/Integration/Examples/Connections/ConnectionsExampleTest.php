<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Connections;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSummary;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Protocols\Preset;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/connections.md` (SSO-2.1, SSO-2.2, SSO-12.5), on
 * the shared example harness: the protocol switches of a published
 * `config/sso.php`, read from the environment; the application's own `cas`
 * driver and `acme` preset, registered by its service provider once the
 * registry resolves; and whether a connection is usable, read from its summary.
 * Each asserts its outcome and a refusal: a protocol switched off creates no
 * connection and leaves its connections unusable, the package's own protocols
 * and presets cannot be replaced, a preset fills in only its own protocol, an
 * ID token signed by an algorithm the preset does not allow is refused, and a
 * flow through a connection that is not usable is refused with
 * `connection_unavailable`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProtocolManager::class)]
#[CoversClass(Preset::class)]
#[CoversClass(ConnectionSummary::class)]
final class ConnectionsExampleTest extends ExampleTestCase
{
    /** @var string The CAS server the application's protocol signs in at. */
    private const string CAS_SERVER = 'https://cas.example.com/cas';

    /** @var list<string> The environment variables the published switches read. */
    private const array SWITCHES = ['SSO_SAML2', 'SSO_OIDC'];

    /**
     * Unset the switches a test set in the environment.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (self::SWITCHES as $switch) {
            putenv($switch);
        }

        parent::tearDown();
    }

    /**
     * With only `SSO_SAML2` set, SAML is available and OIDC is not: a SAML
     * connection is made and usable, an OIDC connection is not created, and one
     * made while OIDC was on is no longer usable, so a flow through it is
     * refused.
     *
     * @return void
     */
    public function testEachProtocolIsAvailableWhileItsSwitchIsOn(): void
    {
        $oidcConnectionId = $this->makeOidcConnection(new FakeOpenIdProvider(clock: $this->clock));

        putenv('SSO_SAML2=true');
        $this->publishSwitches();

        $protocols = app(ProtocolManager::class);

        self::assertTrue($protocols->isAvailable('saml2'));
        self::assertFalse($protocols->isAvailable('oidc'));
        self::assertTrue(app(ConnectionService::class)->get(self::TENANT, $this->makeSamlConnection(new FakeSamlIdentityProvider))?->usable);
        self::assertFalse(app(ConnectionService::class)->get(self::TENANT, $oidcConnectionId)?->usable);

        $refused = app(ConnectionService::class)->create(self::TENANT, 'oidc', 'Example OIDC');

        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, $refused->reason);
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->startFlow(Purpose::SIGN_IN, $oidcConnectionId)->reason);
    }

    /**
     * With neither switch set, neither protocol is available and no connection
     * is created; setting `SSO_OIDC` makes OIDC available, and SAML stays off.
     *
     * @return void
     */
    public function testEachProtocolIsOffUntilItsSwitchIsSet(): void
    {
        $this->publishSwitches();

        $protocols = app(ProtocolManager::class);

        self::assertFalse($protocols->isAvailable('saml2'));
        self::assertFalse($protocols->isAvailable('oidc'));
        self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, app(ConnectionService::class)->create(self::TENANT, 'saml2', 'Example SAML')->reason);

        putenv('SSO_OIDC=true');
        $this->publishSwitches();

        self::assertFalse($protocols->isAvailable('saml2'));
        self::assertTrue($protocols->isAvailable('oidc'));
    }

    /**
     * The application's `cas` driver, registered by its service provider, is
     * registered under exactly that name and available; a connection over it is
     * created, enabled and usable, and a flow through it starts at the CAS
     * server's login page, with the connection's callback as the service. Any
     * other spelling is not registered.
     *
     * @return void
     */
    public function testTheApplicationsProtocolIsRegisteredAndUsed(): void
    {
        app()->register(AppServiceProvider::class);

        $protocols = app(ProtocolManager::class);

        self::assertSame(['saml2', 'oidc', 'cas'], $protocols->names());
        self::assertInstanceOf(CasDriver::class, $protocols->protocol('cas'));
        self::assertTrue($protocols->isAvailable('cas'));
        self::assertFalse($protocols->isRegistered('CAS'));
        self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, app(ConnectionService::class)->create(self::TENANT, 'CAS', 'Acme CAS', ['server_url' => self::CAS_SERVER])->reason);

        $connectionId = $this->makeCasConnection();
        $start        = $this->startFlow(Purpose::SIGN_IN, $connectionId);

        self::assertTrue($start->isStarted());

        $url = (string) $start->navigation?->url();

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        $service = $query['service'] ?? null;

        self::assertSame(self::CAS_SERVER . '/login', Str::before($url, '?'));
        self::assertIsString($service);
        self::assertStringStartsWith('https://sp.example.test/', $service);
        self::assertStringContainsString($connectionId, $service);
        self::assertStringContainsString('?state=', $service);
    }

    /**
     * The application's protocol is available while either protocol switch is
     * on, so its connection is usable only then.
     *
     * @return void
     */
    public function testTheApplicationsProtocolIsAvailableWhileEitherSwitchIsOn(): void
    {
        app()->register(AppServiceProvider::class);

        $connectionId = $this->makeCasConnection();

        config()->set('sso.features.saml2', false);
        config()->set('sso.features.oidc', false);

        self::assertFalse(app(ProtocolManager::class)->isAvailable('cas'));
        self::assertFalse($this->isUsableNow($connectionId));

        config()->set('sso.features.oidc', true);

        self::assertTrue($this->isUsableNow($connectionId));
    }

    /**
     * The package's own protocols cannot be replaced.
     *
     * @return void
     */
    public function testThePackagesProtocolsCannotBeReplaced(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The [saml2] protocol is the package\'s own and cannot be replaced; register yours under another name.');

        app(ProtocolManager::class)->extend('saml2', fn () => new CasDriver);
    }

    /**
     * A connection is usable while it is enabled, its protocol available and
     * its settings complete; a disabled, an incomplete and an unknown
     * connection are not, and a flow through each is refused with the same
     * answer.
     *
     * @return void
     */
    public function testAConnectionIsUsableOnlyWhileEnabledAndComplete(): void
    {
        $tenantId     = self::TENANT;
        $connectionId = $this->makeOidcConnection(new FakeOpenIdProvider(clock: $this->clock));

        // @snippet-start connection-usable
        $usable = app(ConnectionService::class)->get($tenantId, $connectionId)?->usable;
        // @snippet-end connection-usable
        self::assertTrue($usable);
        self::assertTrue(app(ConnectionLifecycle::class)->disable($tenantId, $connectionId)->isSucceeded());
        self::assertFalse($this->isUsableNow($connectionId));

        $incomplete = (string) app(ConnectionService::class)->create($tenantId, 'oidc', 'Incomplete OIDC', ['client_id' => 'client-1'])->connection?->id;

        self::assertTrue(app(ConnectionService::class)->enable($tenantId, $incomplete)->isSucceeded());
        self::assertFalse($this->isUsableNow($incomplete));

        $unknown = strtolower((string) Str::ulid());

        self::assertNull(app(ConnectionService::class)->get($tenantId, $unknown));

        foreach ([$connectionId, $incomplete, $unknown] as $refused) {
            self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->startFlow(Purpose::SIGN_IN, $refused)->reason, $refused);
        }
    }

    /**
     * The application's `acme` preset fills in a new OIDC connection's scopes,
     * ID token algorithms and email mapping; a person links through it at a
     * provider signing with ES256.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheApplicationsPresetFillsInAConnection(): void
    {
        app()->register(AppServiceProvider::class);

        $key          = FakeSigningKey::ec();
        $provider     = (new FakeOpenIdProvider(signingKey: $key, clock: $this->clock))->signWith($key, 'ES256');
        $connectionId = $this->makeAcmeConnection($provider);
        $summary      = app(ConnectionService::class)->get(self::TENANT, $connectionId);

        self::assertNotNull($summary);
        self::assertSame(['openid', 'email', 'profile'], $summary->settings['scopes']);
        self::assertSame(['ES256'], $summary->settings['id_token_algorithms']);
        self::assertSame('email', $summary->attributeMapping['email']);
        self::assertTrue($this->linkThroughFlow($provider, $connectionId, new IdentityReference('App\Models\User', 'person-1'))->isRedeemed());
    }

    /**
     * A connection the `acme` preset filled in refuses an ID token signed by an
     * algorithm the preset does not allow.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAConnectionFromThePresetRefusesAnotherAlgorithm(): void
    {
        app()->register(AppServiceProvider::class);

        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeAcmeConnection($provider);
        $start        = $this->startFlow(Purpose::SIGN_IN, $connectionId);
        $redirect     = $this->respondAtProvider($provider, $connectionId, $start);

        self::assertFalse($redirect->hasCode());
        self::assertSame(FailureReason::SIGNATURE_INVALID->value, $redirect->error);
    }

    /**
     * A shipped preset's name cannot be reused, a preset cannot be registered
     * for a protocol that is not, and a connection takes only a preset of its
     * own protocol that exists.
     *
     * @return void
     */
    public function testAPresetIsRefusedWhereItDoesNotApply(): void
    {
        $protocols = app(ProtocolManager::class);

        self::assertSame(
            'The [google] preset is the package\'s own and cannot be replaced; register yours under another name.',
            self::messageOf(static fn () => $protocols->registerPreset(new Preset('google', 'oidc'))),
        );
        self::assertSame(
            'The [acme_cas] preset is for the [cas] protocol, which is not registered.',
            self::messageOf(static fn () => $protocols->registerPreset(new Preset('acme_cas', 'cas'))),
        );

        app()->register(AppServiceProvider::class);

        $connections = app(ConnectionService::class);

        self::assertEquals([new SettingViolation('preset', ViolationCode::NOT_ALLOWED)], $connections->create(self::TENANT, 'saml2', 'Acme SAML', preset: 'acme')->violations);
        self::assertEquals([new SettingViolation('preset', ViolationCode::UNKNOWN)], $connections->create(self::TENANT, 'oidc', 'Acme OIDC', preset: 'unknown')->violations);
    }

    /**
     * Lay the published protocol switches over the package's configuration,
     * reading the environment as it is now, as Laravel merges a published file
     * with a package's.
     *
     * @return void
     */
    private function publishSwitches(): void
    {
        /** @var array<string, mixed> $published */
        $published = require __DIR__ . '/config/sso.php';

        /** @var array<string, mixed> $package */
        $package = config('sso');

        config()->set('sso', array_replace_recursive($package, $published));
    }

    /**
     * An enabled, usable connection over the application's `cas` protocol.
     *
     * @return string
     */
    private function makeCasConnection(): string
    {
        $connections  = app(ConnectionService::class);
        $created      = $connections->create(self::TENANT, 'cas', 'Acme CAS', ['server_url' => self::CAS_SERVER]);
        $connectionId = (string) $created->connection?->id;

        self::assertTrue($created->isSucceeded());
        self::assertSame(['server_url' => self::CAS_SERVER], $created->connection?->settings);
        self::assertTrue($connections->enable(self::TENANT, $connectionId)->isSucceeded());
        self::assertTrue($connections->get(self::TENANT, $connectionId)?->usable);

        return $connectionId;
    }

    /**
     * An enabled, usable OIDC connection to the provider, filled in by the
     * `acme` preset.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @return string
     */
    private function makeAcmeConnection(FakeOpenIdProvider $provider): string
    {
        $provider->serve($this->fetcher);

        $connections = app(ConnectionService::class);
        $created     = $connections->create(self::TENANT, 'oidc', 'Acme', [
            'issuer'                 => $provider->issuer,
            'authorization_endpoint' => $provider->endpoint('authorization'),
            'token_endpoint'         => $provider->endpoint('token'),
            'jwks_uri'               => $provider->endpoint('jwks'),
            'client_id'              => FakeOpenIdProvider::CLIENT_ID,
            'client_secret'          => FakeOpenIdProvider::CLIENT_SECRET,
        ], preset: 'acme');

        $connectionId = (string) $created->connection?->id;

        self::assertTrue($created->isSucceeded());
        self::assertTrue($connections->enable(self::TENANT, $connectionId)->isSucceeded());
        self::assertTrue($connections->get(self::TENANT, $connectionId)?->usable);

        return $connectionId;
    }

    /**
     * Whether the tenant's connection is usable now, read afresh each time.
     *
     * @param  string  $connectionId
     * @return ?bool
     *
     * @phpstan-impure
     */
    private function isUsableNow(string $connectionId): ?bool
    {
        return app(ConnectionService::class)->get(self::TENANT, $connectionId)?->usable;
    }

    /**
     * The message of the `InvalidArgumentException` the call throws.
     *
     * @param  \Closure(): mixed  $call
     * @return string
     */
    private static function messageOf(\Closure $call): string
    {
        try {
            $call();
        } catch (\InvalidArgumentException $exception) {
            return $exception->getMessage();
        }

        self::fail('The call threw nothing.');
    }
}
