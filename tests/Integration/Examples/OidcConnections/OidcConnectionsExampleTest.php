<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OidcConnections;

use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ViewErrorBag;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSummary;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\ImportSaver;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Metadata\DiscoveryImporter;
use SineMacula\Laravel\Sso\Metadata\ProposedOidcSettings;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/oidc-connections.md` (SSO-2.8, SSO-2.11,
 * SSO-12.5), on the shared example harness, with the application's own tenant:
 * the import endpoint fetches the issuer's discovery document and keys and
 * shows the administrator exactly the settings, client authentication methods
 * and keys the guide shows, writing nothing; a document naming another issuer
 * goes back with `issuer_mismatch`, and an import past the connection's
 * metadata limit goes back with the wait. The save endpoint stores the accepted
 * proposal with the client, as the acting administrator, after which the
 * connection is usable with no keys stored; a new import of the same settings
 * saved again renews the connection on the record alone; and a stale caller is
 * refused with `freshness_required`, changing nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-type SaveInput array{
 *     tenant: \Tests\Integration\Examples\OidcConnections\Tenant,
 *     connection: \SineMacula\Laravel\Sso\Connections\ConnectionSummary,
 *     proposed: \SineMacula\Laravel\Sso\Metadata\ProposedOidcSettings,
 *     client_id: string,
 *     secret: string,
 *     actor: \SineMacula\Laravel\Sso\Administration\ActingIdentity
 * }
 *
 * @internal
 */
#[CoversClass(DiscoveryImporter::class)]
#[CoversClass(ProposedOidcSettings::class)]
#[CoversClass(ImportSaver::class)]
final class OidcConnectionsExampleTest extends ExampleTestCase
{
    /** @var string The issuer the guide imports from. */
    private const string ISSUER = 'https://login.example.com/tenant-a';

    /** @var string The client the administrator registered with the provider. */
    private const string CLIENT_ID = 'acme-portal';

    /** @var string That client's secret. */
    private const string CLIENT_SECRET = 'acme-portal-secret';

    /** @var \Tests\Integration\Examples\OidcConnections\Tenant The tenant whose connection is set up. */
    private Tenant $tenant;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var \SineMacula\Laravel\Sso\Connections\ConnectionSummary The tenant's OIDC connection, not yet filled in. */
    private ConnectionSummary $connection;

    /**
     * Keep sessions in memory, serve the provider the guide imports from, with
     * an RSA key and a P-256 key, and make the tenant's bare OIDC connection,
     * which allows both keys' algorithms.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('session.driver', 'array');

        $signing = FakeSigningKey::rsa('abc');

        $this->tenant   = new Tenant(self::TENANT);
        $this->provider = (new FakeOpenIdProvider(self::ISSUER, $signing, $this->clock))
            ->unpublish('abc')
            ->publish($signing, 'RS256')
            ->publish(FakeSigningKey::ec('def'), 'ES256')
            ->withDiscovery([
                'id_token_signing_alg_values_supported' => ['RS256', 'ES256'],
                'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'private_key_jwt'],
            ])
            ->serve($this->fetcher);

        $created = app(ConnectionService::class)->create(self::TENANT, 'oidc', 'Acme login', ['id_token_algorithms' => ['RS256', 'ES256']]);

        self::assertNotNull($created->connection);

        $this->connection = $created->connection;
    }

    /**
     * The import reads the document from under the issuer, path included, and
     * the JWKS it names, and proposes exactly what the guide shows, writing
     * nothing to the connection.
     *
     * @return void
     */
    public function testTheImportProposesWhatTheIssuerPublishes(): void
    {
        $shown = $this->import();

        self::assertIsArray($shown);
        self::assertEquals([
            'issuer'                 => self::ISSUER,
            'authorization_endpoint' => self::ISSUER . '/authorize',
            'token_endpoint'         => self::ISSUER . '/token',
            'jwks_uri'               => self::ISSUER . '/jwks',
            'userinfo_endpoint'      => self::ISSUER . '/userinfo',
            'returns_iss'            => true,
            'id_token_algorithms'    => ['RS256', 'ES256'],
        ], $shown['settings']);
        self::assertSame(['client_secret_basic', 'private_key_jwt'], $shown['auth_methods']);
        self::assertSame([
            ['kid' => 'abc', 'kty' => 'RSA', 'alg' => 'RS256'],
            ['kid' => 'def', 'kty' => 'EC', 'alg' => 'ES256'],
        ], $shown['keys']);

        $this->fetcher->assertFetched('https://login.example.com/tenant-a/.well-known/openid-configuration', FetchPurpose::DISCOVERY);
        $this->fetcher->assertFetched(self::ISSUER . '/jwks', FetchPurpose::JWKS);

        self::assertArrayNotHasKey('issuer', $this->stored()->settings);
    }

    /**
     * A document naming another issuer than the one given goes back with
     * `issuer_mismatch` under `issuer`.
     *
     * @return void
     */
    public function testARefusedImportGoesBackWithItsReason(): void
    {
        $this->provider->withDiscovery(['issuer' => 'https://login.example.com/tenant-b']);

        self::assertSame(['issuer' => ['issuer_mismatch']], self::errors($this->import()));
        self::assertArrayNotHasKey('issuer', $this->stored()->settings);
    }

    /**
     * An import past the connection's metadata limit goes back with the seconds
     * until its window ends, having fetched nothing.
     *
     * @return void
     */
    public function testAnImportPastTheLimitGoesBackWithTheWait(): void
    {
        config()->set('sso.rate_limits.metadata.per_connection', ['max' => 1, 'decay_seconds' => 3600]);

        self::assertIsArray($this->import());
        self::assertCount(2, $this->fetcher->requests());

        self::assertSame(['issuer' => ['Try again in 1800 seconds.']], self::errors($this->import()));
        self::assertCount(2, $this->fetcher->requests());
    }

    /**
     * Saving the accepted proposal with the client asks for the connection's
     * trust, updates the connection as the administrator, and leaves it
     * complete with no keys stored, so enabling it makes it usable.
     *
     * @return void
     */
    public function testSavingTheProposalMakesTheConnectionUsable(): void
    {
        $reported = $this->recordUpdates();
        $saved    = $this->save($this->proposed());

        self::assertTrue($saved->isChanged());
        self::assertSame(ConnectionStatus::UPDATED, $saved->status);
        self::assertEqualsCanonicalizing(
            ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'returns_iss', 'client_id', 'client_secret'],
            $saved->changedSettings,
        );
        $this->freshness->assertAsked(FreshnessOperation::CONNECTION_TRUST);

        self::assertSame([['App\Models\User', '42']], array_map(
            static fn (ConnectionUpdated $event): array => [$event->context->actingIdentityMorphClass, $event->context->actingIdentityId],
            $reported->getArrayCopy(),
        ));

        $stored = $this->stored();

        self::assertSame([self::ISSUER, self::ISSUER . '/jwks', self::CLIENT_ID], [$stored->settings['issuer'], $stored->settings['jwks_uri'], $stored->settings['client_id']]);
        self::assertTrue(app(ConnectionService::class)->enable(self::TENANT, $this->connection->id)->isChanged());
        self::assertTrue($this->stored()->usable);
    }

    /**
     * A new import of the same settings, saved again, changes nothing but the
     * fetch it is counted from, and reports that alone.
     *
     * @return void
     */
    public function testSavingANewImportOfTheSameSettingsRenewsIt(): void
    {
        $this->save($this->proposed());
        $this->clock->advance(86400);

        $reported = $this->recordUpdates();
        $proposed = $this->proposed();
        $renewed  = app(ImportSaver::class)->save(self::TENANT, $this->connection->id, ['settings' => $proposed->settings()], $proposed->fetch());

        self::assertSame(ConnectionStatus::UNCHANGED, $renewed->status);
        self::assertSame([['metadata_fetched_at']], array_map(static fn (ConnectionUpdated $event): array => $event->changedSettings, $reported->getArrayCopy()));
    }

    /**
     * A caller whose authentication is not fresh enough for the connection's
     * trust is refused with `freshness_required`, and the connection keeps what
     * it had.
     *
     * @return void
     */
    public function testAStaleCallerCannotSave(): void
    {
        $proposed = $this->proposed();

        $this->freshness->staleFor(FreshnessOperation::CONNECTION_TRUST);

        $refused = $this->save($proposed);

        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $refused->reason);
        self::assertArrayNotHasKey('issuer', $this->stored()->settings);
    }

    /**
     * Run the import endpoint for the tenant's connection, and answer what it
     * answers.
     *
     * @return mixed
     */
    private function import(): mixed
    {
        return self::atImport(['tenant' => $this->tenant, 'connection' => $this->connection]);
    }

    /**
     * The import endpoint, given its input.
     *
     * @param  array{tenant: \Tests\Integration\Examples\OidcConnections\Tenant, connection: \SineMacula\Laravel\Sso\Connections\ConnectionSummary}  $input
     * @return mixed
     */
    private static function atImport(array $input): mixed
    {
        return require __DIR__ . '/admin/import.php';
    }

    /**
     * What a proposed import of the issuer proposes.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\ProposedOidcSettings
     */
    private function proposed(): ProposedOidcSettings
    {
        $shown = $this->import();

        self::assertIsArray($shown);
        self::assertInstanceOf(ProposedOidcSettings::class, $shown['proposed']);

        return $shown['proposed'];
    }

    /**
     * Run the save endpoint for the proposal, with the client, as the
     * administrator, and answer its result.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\ProposedOidcSettings  $proposed
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     */
    private function save(ProposedOidcSettings $proposed): ConnectionResult
    {
        $result = self::atSave([
            'tenant'     => $this->tenant,
            'connection' => $this->connection,
            'proposed'   => $proposed,
            'client_id'  => self::CLIENT_ID,
            'secret'     => self::CLIENT_SECRET,
            'actor'      => new ActingIdentity('App\Models\User', '42'),
        ]);

        self::assertInstanceOf(ConnectionResult::class, $result);

        return $result;
    }

    /**
     * The save endpoint, given its input.
     *
     * @param  SaveInput  $input
     * @return mixed
     */
    private static function atSave(array $input): mixed
    {
        return require __DIR__ . '/admin/save.php';
    }

    /**
     * The tenant's connection as it is stored now.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSummary
     */
    private function stored(): ConnectionSummary
    {
        $stored = app(ConnectionService::class)->get(self::TENANT, $this->connection->id);

        self::assertNotNull($stored);

        return $stored;
    }

    /**
     * Record each `ConnectionUpdated` reported from now on.
     *
     * @return \ArrayObject<int, \SineMacula\Laravel\Sso\Events\ConnectionUpdated>
     */
    private function recordUpdates(): \ArrayObject
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\ConnectionUpdated> $reported */
        $reported = new \ArrayObject;

        Event::listen(ConnectionUpdated::class, static function (ConnectionUpdated $event) use ($reported): void {
            $reported->append($event);
        });

        return $reported;
    }

    /**
     * The errors an endpoint went back with, by field.
     *
     * @param  mixed  $response
     * @return array<string, list<string>>
     */
    private static function errors(mixed $response): array
    {
        self::assertInstanceOf(RedirectResponse::class, $response);

        $errors = $response->getSession()?->get('errors');

        self::assertInstanceOf(ViewErrorBag::class, $errors);

        /** @var array<string, list<string>> */
        return $errors->getBag('default')->toArray();
    }
}
