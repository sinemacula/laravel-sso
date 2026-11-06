<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Metadata\DiscoveryImport;
use SineMacula\Laravel\Sso\Metadata\DiscoveryImporter;
use SineMacula\Laravel\Sso\Metadata\OidcMetadata;
use SineMacula\Laravel\Sso\Metadata\ProposedOidcSettings;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\RateLimit;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for importing an OpenID provider's discovery document and JWKS
 * (SSO-2.8, SSO-2.9, SSO-2.11, SSO-7.3), through the public import with the
 * fake provider and hostile documents: the settings proposed exactly, the URL
 * found by appending to the issuer, path included; each refusal in its order; a
 * named connection's own allow-list and rate limit; the caps at, under and
 * over; and nothing written, trusted, reported or logged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DiscoveryImporter::class)]
#[CoversClass(DiscoveryImport::class)]
#[CoversClass(ProposedOidcSettings::class)]
#[CoversClass(OidcMetadata::class)]
final class DiscoveryImporterTest extends TestCase
{
    use CapturesLogs, DumpsValues, RecordsEventSequences, UsesConnections;

    /** @var string The tenant importing. */
    private const string TENANT = 'tenant-1';

    /** @var string The issuer imported from. */
    private const string ISSUER = FakeOpenIdProvider::ISSUER;

    /** @var string Where the issuer's discovery document is. */
    private const string DISCOVERY = self::ISSUER . '/.well-known/openid-configuration';

    /** @var int The default cap on a discovery document and a JWKS, in bytes. */
    private const int CAP = 65536;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's RSA key, generated once. */
    private static ?FakeSigningKey $rsa = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey An elliptic curve key, generated once. */
    private static ?FakeSigningKey $ec = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the importer fetches through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider imported from. */
    private FakeOpenIdProvider $provider;

    /**
     * Bind a fixed clock and a fake fetcher serving the provider, switch OIDC
     * on, create the tables, and record events and logs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher  = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(self::ISSUER, self::rsa()))->serve($this->fetcher);

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.saml2', true);

        $this->usePackageTables();

        $this->captureLogs();
        $this->startRecordingEvents();
    }

    /**
     * An import proposes exactly what the document gives and each admitted
     * key's `kid`, `kty` and `alg`, having fetched the document and the JWKS
     * once each, under their caps, and writes, reports and logs nothing.
     *
     * @return void
     */
    public function testAnImportProposesWhatTheDocumentGives(): void
    {
        $this->provider->publish(self::ec(), 'ES256');

        $result = $this->importer()->import(self::TENANT, self::ISSUER);

        self::assertTrue($result->isProposed());
        self::assertFalse($result->isRefused());
        self::assertFalse($result->isRateLimited());
        self::assertSame([null, null], [$result->reason, $result->retryAfter]);
        self::assertSame([
            'issuer'                 => self::ISSUER,
            'authorization_endpoint' => self::ISSUER . '/authorize',
            'token_endpoint'         => self::ISSUER . '/token',
            'jwks_uri'               => self::ISSUER . '/jwks',
            'userinfo_endpoint'      => self::ISSUER . '/userinfo',
            'returns_iss'            => true,
            'id_token_algorithms'    => ['RS256', 'PS256', 'ES256'],
        ], $result->proposed->settings());
        self::assertSame(['client_secret_basic', 'client_secret_post', 'private_key_jwt'], $result->proposed->authMethods());
        self::assertSame([
            ['kid' => 'rsa-1', 'kty' => 'RSA', 'alg' => null],
            ['kid' => 'ec-1', 'kty' => 'EC', 'alg' => 'ES256'],
        ], $result->proposed->keys());
        self::assertSame([
            ['discovery', self::DISCOVERY, self::CAP],
            ['jwks', self::ISSUER . '/jwks', self::CAP],
        ], $this->requests());

        self::assertSame(0, Connection::query()->count());
        self::assertSame(0, RateLimit::query()->count());
        self::assertSame([], $this->capturedLogRecords());
        $this->assertNoEvents();
    }

    /**
     * Rows of `[issuer, discovery URL]`: the document is found by appending to
     * the issuer, path included, with any trailing slash removed.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideIssuers(): iterable
    {
        yield from [
            'an issuer with a path'           => ['https://op.example.test/tenant/a', 'https://op.example.test/tenant/a/.well-known/openid-configuration'],
            'an issuer with a trailing slash' => ['https://op.example.test/', 'https://op.example.test/.well-known/openid-configuration'],
            'a path with a trailing slash'    => ['https://op.example.test/a/', 'https://op.example.test/a/.well-known/openid-configuration'],
        ];
    }

    /**
     * The discovery URL appends to the issuer, never inserts as RFC 8414 does,
     * and the document must name the issuer exactly as it was given.
     *
     * @param  string  $issuer
     * @param  string  $url
     * @return void
     */
    #[DataProvider('provideIssuers')]
    public function testTheDocumentIsFoundByAppendingToTheIssuer(string $issuer, string $url): void
    {
        $fetcher = new FakeFetcher;

        $this->app?->instance(Fetcher::class, $fetcher);

        (new FakeOpenIdProvider($issuer, self::rsa()))->serve($fetcher);

        $result = $this->importer()->import(self::TENANT, $issuer);

        self::assertSame($issuer, $result->proposed?->settings()['issuer'] ?? null);
        self::assertSame($url, $fetcher->requests()[0]->url);
    }

    /**
     * Rows of `[changes, returns iss]`: the document's RFC 9207 flag.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function provideFlags(): iterable
    {
        yield from [
            'advertised'     => [['authorization_response_iss_parameter_supported' => true], true],
            'advertised off' => [['authorization_response_iss_parameter_supported' => false], false],
            'not advertised' => [['authorization_response_iss_parameter_supported' => null], false],
        ];
    }

    /**
     * `returns_iss` is true exactly when the document advertises the parameter.
     *
     * @param  array<string, mixed>  $changes
     * @param  bool  $returnsIss
     * @return void
     */
    #[DataProvider('provideFlags')]
    public function testReturnsIssFollowsTheFlag(array $changes, bool $returnsIss): void
    {
        $this->provider->withDiscovery($changes);

        self::assertSame($returnsIss, $this->importer()->import(self::TENANT, self::ISSUER)->proposed?->settings()['returns_iss'] ?? null);
    }

    /**
     * A document without a UserInfo endpoint or client authentication methods
     * proposes neither.
     *
     * @return void
     */
    public function testWhatTheDocumentLeavesOutIsNotProposed(): void
    {
        $this->provider->withDiscovery(['userinfo_endpoint' => null, 'token_endpoint_auth_methods_supported' => null]);

        $proposed = $this->importer()->import(self::TENANT, self::ISSUER)->proposed;

        self::assertSame(['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'returns_iss', 'id_token_algorithms'], array_keys($proposed?->settings() ?? []));
        self::assertSame([], $proposed?->authMethods());
    }

    /**
     * While OIDC is off every import is `protocol_unavailable`, before the
     * issuer is judged, a connection is looked up or anything is fetched.
     *
     * @return void
     */
    public function testAnImportIsRefusedWhileOidcIsOff(): void
    {
        config()->set('sso.features.oidc', false);

        $result = $this->importer()->import(self::TENANT, 'http://not-an-issuer', 'unknown-connection');

        self::assertSame([FailureReason::PROTOCOL_UNAVAILABLE, true, false, false], [$result->reason, $result->isRefused(), $result->isProposed(), $result->isRateLimited()]);
        $this->fetcher->assertNothingFetched();
    }

    /**
     * Rows of `[issuer]`: what is not a valid issuer setting.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideInvalidIssuers(): iterable
    {
        yield from [
            'empty'         => [''],
            'http'          => ['http://op.example.test'],
            'with a query'  => ['https://op.example.test?a=1'],
            'with userinfo' => ['https://user@op.example.test'],
            'a fragment'    => ['https://op.example.test#a'],
            'no host'       => ['https://'],
            'not a URL'     => ['op.example.test'],
        ];
    }

    /**
     * An issuer that is not a valid setting is `settings_invalid`, before a
     * connection is looked up or anything is fetched.
     *
     * @param  string  $issuer
     * @return void
     */
    #[DataProvider('provideInvalidIssuers')]
    public function testAnInvalidIssuerIsRefused(string $issuer): void
    {
        self::assertSame(FailureReason::SETTINGS_INVALID, $this->importer()->import(self::TENANT, $issuer, 'unknown-connection')->reason);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * Rows of `[attributes, tenant]`: a connection that is not the tenant's
     * OIDC connection.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideOtherConnections(): iterable
    {
        yield from [
            'another tenants'   => [['tenant_id' => 'tenant-2'], self::TENANT],
            'a SAML connection' => [['protocol' => 'saml2'], self::TENANT],
        ];
    }

    /**
     * A connection that is another tenant's or not OIDC is
     * `connection_not_found` exactly as an unknown one, with nothing counted or
     * fetched.
     *
     * @param  array<string, mixed>  $attributes
     * @param  string  $tenant
     * @return void
     */
    #[DataProvider('provideOtherConnections')]
    public function testAConnectionThatIsNotTheTenantsOidcConnectionIsNotFound(array $attributes, string $tenant): void
    {
        $connection = $this->makeConnection($attributes);

        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $this->importer()->import($tenant, self::ISSUER, $connection->id)->reason);
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $this->importer()->import($tenant, self::ISSUER, '01jbunknownconnection00000')->reason);
        self::assertSame(0, RateLimit::query()->count());

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A named connection's own allow-list holds the JWKS, whatever the document
     * supports, and with none named the document's algorithms do.
     *
     * @return void
     */
    public function testANamedConnectionsAllowListHoldsTheJwks(): void
    {
        $this->provider->publish(self::ec(), 'ES256')->publish(self::rsa()->withKid('ps-1'), 'PS256');

        $unnamed = [
            ['kid' => 'rsa-1', 'kty' => 'RSA', 'alg' => null],
            ['kid' => 'ec-1', 'kty' => 'EC', 'alg' => 'ES256'],
            ['kid' => 'ps-1', 'kty' => 'RSA', 'alg' => 'PS256'],
        ];

        $es256   = $this->makeConnection(['settings' => ['id_token_algorithms' => ['ES256']]]);
        $default = $this->makeConnection();

        self::assertSame([$unnamed[0], $unnamed[1]], $this->importer()->import(self::TENANT, self::ISSUER, $es256->id)->proposed?->keys());
        self::assertSame([$unnamed[0]], $this->importer()->import(self::TENANT, self::ISSUER, $default->id)->proposed?->keys());
        self::assertSame($unnamed, $this->importer()->import(self::TENANT, self::ISSUER)->proposed?->keys());
    }

    /**
     * An import naming a connection counts against its metadata limit before it
     * fetches: past it, it is rate limited until the window ends, with nothing
     * fetched; one naming no connection is not counted.
     *
     * @return void
     */
    public function testAnImportNamingAConnectionIsRateLimited(): void
    {
        config()->set('sso.rate_limits.metadata.per_connection', ['max' => 2, 'decay_seconds' => 3600]);

        $connection = $this->makeConnection();

        self::assertTrue($this->importer()->import(self::TENANT, self::ISSUER, $connection->id)->isProposed());
        self::assertTrue($this->importer()->import(self::TENANT, self::ISSUER, $connection->id)->isProposed());

        $limited = $this->importer()->import(self::TENANT, self::ISSUER, $connection->id);

        self::assertSame([true, false, false], [$limited->isRateLimited(), $limited->isRefused(), $limited->isProposed()]);
        self::assertSame([FailureReason::RATE_LIMITED, 1800, null], [$limited->reason, $limited->retryAfter, $limited->proposed]);
        self::assertCount(4, $this->fetcher->requests());

        self::assertTrue($this->importer()->import(self::TENANT, self::ISSUER)->isProposed());
        self::assertTrue($this->importer()->import(self::TENANT, self::ISSUER)->isProposed());
        self::assertTrue($this->importer()->import(self::TENANT, self::ISSUER)->isProposed());
    }

    /**
     * Rows of `[response, reason]`: how a fetch of the document or the JWKS may
     * end without a response of `2xx`. A redirect to a private address is
     * refused by the fetcher, which answers it so.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideFetchFailures(): iterable
    {
        yield from [
            'refused, a redirect to a private address' => [FetchResult::refused(), FailureReason::FETCH_REFUSED],
            'failed'                                   => [FetchResult::failed(), FailureReason::FETCH_FAILED],
            'a server error'                           => [FetchResult::fetched(500, [], '{}'), FailureReason::FETCH_FAILED],
            'not found'                                => [FetchResult::fetched(404, [], '{}'), FailureReason::FETCH_FAILED],
            'a status just over 2xx'                   => [FetchResult::fetched(300, [], '{}'), FailureReason::FETCH_FAILED],
        ];
    }

    /**
     * A discovery fetch that brings no `2xx` response refuses the import, and
     * the JWKS is not fetched.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideFetchFailures')]
    public function testADiscoveryFetchFailureRefusesTheImport(FetchResult $response, FailureReason $reason): void
    {
        $this->provider->respond('discovery', $response);

        self::assertSame($reason, $this->importer()->import(self::TENANT, self::ISSUER)->reason);
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * A JWKS fetch that brings no `2xx` response refuses the import.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideFetchFailures')]
    public function testAJwksFetchFailureRefusesTheImport(FetchResult $response, FailureReason $reason): void
    {
        $this->provider->respond('jwks', $response);

        self::assertSame($reason, $this->importer()->import(self::TENANT, self::ISSUER)->reason);
        self::assertCount(2, $this->fetcher->requests());
    }

    /**
     * Rows of `[changes, reason]`: hostile documents.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideHostileDocuments(): iterable
    {
        yield from [
            'an issuer differing by a trailing slash' => [['issuer' => self::ISSUER . '/'], FailureReason::ISSUER_MISMATCH],
            'an issuer differing by case'             => [['issuer' => 'https://OP.example.test'], FailureReason::ISSUER_MISMATCH],
            'an issuer differing by a path'           => [['issuer' => self::ISSUER . '/a'], FailureReason::ISSUER_MISMATCH],
            'an http endpoint'                        => [['token_endpoint' => 'http://op.example.test/token'], FailureReason::DISCOVERY_INVALID],
            'an endpoint with userinfo'               => [['authorization_endpoint' => 'https://a:b@op.example.test/authorize'], FailureReason::DISCOVERY_INVALID],
            'no JWKS URI'                             => [['jwks_uri' => null], FailureReason::DISCOVERY_INVALID],
            'response types without code'             => [['response_types_supported' => ['id_token']], FailureReason::DISCOVERY_INVALID],
            'PKCE without S256'                       => [['code_challenge_methods_supported' => ['plain']], FailureReason::DISCOVERY_INVALID],
            'an RFC 9207 flag that is not a boolean'  => [['authorization_response_iss_parameter_supported' => 'true'], FailureReason::DISCOVERY_INVALID],
            'an algorithm list that is not a list'    => [['id_token_signing_alg_values_supported' => ['RS256' => true]], FailureReason::DISCOVERY_INVALID],
        ];
    }

    /**
     * A hostile document refuses the import with its reason, and its JWKS is
     * not fetched.
     *
     * @param  array<string, mixed>  $changes
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideHostileDocuments')]
    public function testAHostileDocumentRefusesTheImport(array $changes, FailureReason $reason): void
    {
        $this->provider->withDiscovery($changes);

        self::assertSame($reason, $this->importer()->import(self::TENANT, self::ISSUER)->reason);
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * Rows of `[body]`: discovery bodies hostile before any member is read.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideHostileBodies(): iterable
    {
        $backslash = chr(92);
        $issuer    = '"issuer":"' . self::ISSUER . '"';
        $rest      = substr((string) json_encode((new FakeOpenIdProvider(self::ISSUER, self::rsa()))->discovery(), JSON_UNESCAPED_SLASHES), 1);

        yield from [
            'not an object'        => ['[]'],
            'the issuer repeated'  => ['{' . $issuer . ',' . $rest],
            'the issuer escaped'   => ['{"' . $backslash . 'u0069ssuer":"' . self::ISSUER . '",' . $rest],
            'nested members twice' => ['{"x":{"a":1,"a":2},' . $rest],
        ];
    }

    /**
     * A body not one strict JSON object refuses the import as
     * `discovery_invalid`.
     *
     * @param  string  $body
     * @return void
     */
    #[DataProvider('provideHostileBodies')]
    public function testAHostileBodyRefusesTheImport(string $body): void
    {
        $this->provider->respond('discovery', FetchResult::fetched(200, [], $body));

        self::assertSame(FailureReason::DISCOVERY_INVALID, $this->importer()->import(self::TENANT, self::ISSUER)->reason);
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * Rows of `[offset, reason]`: a discovery document's length against its
     * cap.
     *
     * @return iterable<string, array{0: int, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideCapOffsets(): iterable
    {
        yield from [
            'under the cap' => [-1, null],
            'at the cap'    => [0, null],
            'over the cap'  => [1, FailureReason::FETCH_FAILED],
        ];
    }

    /**
     * A discovery document is imported at its cap and under it, and refused
     * over it.
     *
     * @param  int  $offset
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideCapOffsets')]
    public function testTheDiscoveryCapHolds(int $offset, ?FailureReason $reason): void
    {
        $this->provider->respond('discovery', FetchResult::fetched(200, [], self::paddedTo(self::CAP + $offset, $this->provider->discovery())));

        self::assertSame($reason, $this->importer()->import(self::TENANT, self::ISSUER)->reason);
    }

    /**
     * A JWKS is imported at its cap and under it, and refused over it.
     *
     * @param  int  $offset
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideCapOffsets')]
    public function testTheJwksCapHolds(int $offset, ?FailureReason $reason): void
    {
        $this->provider->respond('jwks', FetchResult::fetched(200, [], self::paddedTo(self::CAP + $offset, $this->provider->jwks())));

        self::assertSame($reason, $this->importer()->import(self::TENANT, self::ISSUER)->reason);
    }

    /**
     * Rows of `[hostile JWK]`: a key the package never admits, built as it is
     * needed, since most need a key of their own.
     *
     * @return iterable<string, array{0: \Closure(): array<string, mixed>}>
     */
    public static function provideInadmissibleKeys(): iterable
    {
        yield from [
            'an oct key planted'      => [static fn (): array => ['kty' => 'oct', 'kid' => 'planted', 'k' => 'c2VjcmV0']],
            'a private key published' => [static fn (): array => self::rsa()->withKid('published')->privateJwk()],
            'a 1024-bit key'          => [static fn (): array => FakeSigningKey::rsa('weak', 1024)->jwk()],
            'ES512 on a P-256 key'    => [static fn (): array => self::ec()->withKid('curve')->jwk('ES512')],
            'use enc'                 => [static fn (): array => self::rsa()->withKid('enc')->jwk(null, 'enc')],
            'key_ops without verify'  => [static fn (): array => self::rsa()->withKid('ops')->jwk(null, 'sig', ['key_ops' => ['sign']])],
            'an empty kid'            => [static fn (): array => self::rsa()->withKid('')->jwk()],
        ];
    }

    /**
     * A key the package never admits is left out when an admitted key stands
     * beside it, and alone leaves no admitted key: `jwks_invalid`.
     *
     * @param  \Closure(): array<string, mixed>  $jwk
     * @return void
     */
    #[DataProvider('provideInadmissibleKeys')]
    public function testAKeyThePackageNeverAdmitsIsLeftOut(\Closure $jwk): void
    {
        $hostile = $jwk();

        $this->provider->publishJwk($hostile)->withDiscovery(['id_token_signing_alg_values_supported' => ['RS256', 'ES256', 'ES512']]);

        self::assertSame([['kid' => 'rsa-1', 'kty' => 'RSA', 'alg' => null]], $this->importer()->import(self::TENANT, self::ISSUER)->proposed?->keys());

        $this->provider->respond('jwks', FetchResult::fetched(200, [], (string) json_encode(['keys' => [$hostile]], JSON_UNESCAPED_SLASHES)));

        self::assertSame(FailureReason::JWKS_INVALID, $this->importer()->import(self::TENANT, self::ISSUER)->reason);
    }

    /**
     * Rows of `[body builder]`: a JWKS refused whole.
     *
     * @return iterable<string, array{0: \Closure(array<string, mixed>): string}>
     */
    public static function provideHostileJwks(): iterable
    {
        yield from [
            'a duplicate admissible kid'  => [static fn (array $jwk): string => (string) json_encode(['keys' => [$jwk, $jwk]])],
            'no keys'                     => [static fn (array $jwk): string => (string) json_encode(['keys' => []])],
            'no keys member'              => [static fn (array $jwk): string => (string) json_encode(['other' => [$jwk]])],
            'keys that are a map'         => [static fn (array $jwk): string => (string) json_encode(['keys' => ['a' => $jwk]])],
            'keys an object of a list'    => [static fn (array $jwk): string => (string) json_encode(['keys' => (object) [$jwk]])],
            'key_ops an object of a list' => [static fn (array $jwk): string => (string) json_encode(['keys' => [[...$jwk, 'key_ops' => (object) ['verify']]]])],
            'a key that is a string'      => [static fn (array $jwk): string => (string) json_encode(['keys' => ['key']])],
            'a list'                      => [static fn (array $jwk): string => (string) json_encode([$jwk])],
            'not JSON'                    => [static fn (array $jwk): string => '<html></html>'],
            'a repeated member'           => [static fn (array $jwk): string => '{"keys":[],"keys":[' . json_encode($jwk) . ']}'],
            'a nested repeated member'    => [static fn (array $jwk): string => '{"keys":[{"kty":"oct",' . substr((string) json_encode($jwk), 1) . ']}'],
            'an escaped nested member'    => [static fn (array $jwk): string => '{"keys":[{"' . chr(92) . 'u006bty":"oct",' . substr((string) json_encode($jwk), 1) . ']}'],
        ];
    }

    /**
     * A hostile JWKS refuses the import whole, as `jwks_invalid`.
     *
     * @param  \Closure(array<string, mixed>): string  $body
     * @return void
     */
    #[DataProvider('provideHostileJwks')]
    public function testAHostileJwksRefusesTheImport(\Closure $body): void
    {
        $this->provider->respond('jwks', FetchResult::fetched(200, [], $body(self::rsa()->jwk())));

        self::assertSame(FailureReason::JWKS_INVALID, $this->importer()->import(self::TENANT, self::ISSUER)->reason);
    }

    /**
     * Rows of `[keys, proposed]`: how many keys a JWKS holds against its limit.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideKeyCounts(): iterable
    {
        yield from [
            '49 keys' => [49, true],
            '50 keys' => [50, true],
            '51 keys' => [51, false],
        ];
    }

    /**
     * A JWKS of 50 keys is imported, and one of 51 refused.
     *
     * @param  int  $count
     * @param  bool  $proposed
     * @return void
     */
    #[DataProvider('provideKeyCounts')]
    public function testTheKeyLimitHolds(int $count, bool $proposed): void
    {
        $this->provider->respond('jwks', FetchResult::fetched(200, [], self::jwksOf($count)));

        $result = $this->importer()->import(self::TENANT, self::ISSUER);

        self::assertSame($proposed ? null : FailureReason::JWKS_INVALID, $result->reason);
        self::assertCount($proposed ? $count : 0, $result->proposed?->keys() ?? []);
    }

    /**
     * An import refuses to run inside a transaction on the storage connection,
     * before it looks anything up or fetches.
     *
     * @return void
     */
    public function testAnImportRefusesToRunInsideATransaction(): void
    {
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        try {
            $this->importer()->import(self::TENANT, self::ISSUER);
            self::fail('The import ran inside a transaction.');
        } catch (\LogicException $exception) {
            self::assertSame('A discovery import runs outside any transaction on the storage connection, since it fetches while it is called.', $exception->getMessage());
        } finally {
            $database->rollBack();
        }

        $this->fetcher->assertNothingFetched();
    }

    /**
     * Rows of `[tenant, thrown]`: a tenant id's length against what the table
     * holds.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideTenants(): iterable
    {
        yield from [
            'empty'     => ['', true],
            '1 byte'    => ['a', false],
            '255 bytes' => [str_repeat('a', 255), false],
            '256 bytes' => [str_repeat('a', 256), true],
        ];
    }

    /**
     * A tenant id the table cannot hold is an `InvalidArgumentException`.
     *
     * @param  string  $tenant
     * @param  bool  $thrown
     * @return void
     */
    #[DataProvider('provideTenants')]
    public function testATenantIdIsChecked(string $tenant, bool $thrown): void
    {
        if ($thrown) {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessage('A tenant id is 1 to 255 bytes.');
        }

        self::assertTrue($this->importer()->import($tenant, self::ISSUER)->isProposed());
    }

    /**
     * An import is refused only for its own reasons, and rate limited for at
     * least a second.
     *
     * @return void
     */
    public function testAnImportEndsOnlyAsItMay(): void
    {
        foreach (DiscoveryImport::REFUSALS as $reason) {
            self::assertSame($reason, DiscoveryImport::refused($reason)->reason);
        }

        self::assertSame([
            FailureReason::PROTOCOL_UNAVAILABLE,
            FailureReason::SETTINGS_INVALID,
            FailureReason::CONNECTION_NOT_FOUND,
            FailureReason::FETCH_REFUSED,
            FailureReason::FETCH_FAILED,
            FailureReason::ISSUER_MISMATCH,
            FailureReason::DISCOVERY_INVALID,
            FailureReason::JWKS_INVALID,
        ], DiscoveryImport::REFUSALS);

        self::assertSame(1, DiscoveryImport::rateLimited(1)->retryAfter);

        try {
            DiscoveryImport::refused(FailureReason::RATE_LIMITED);
            self::fail('An import was refused for a reason of no import.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A discovery import is not refused for [rate_limited].', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A rate limited discovery import may be tried again after at least 1 second.');

        DiscoveryImport::rateLimited(0);
    }

    /**
     * A proposal shows no value in a dump or `json_encode()`, holds no member
     * of a key beyond `kid`, `kty` and `alg`, and refuses to be serialised.
     *
     * @return void
     */
    public function testAProposalHoldsItsValuesOutOfEveryDump(): void
    {
        $proposed = $this->importer()->import(self::TENANT, self::ISSUER)->proposed;
        $expected = [
            'settings'     => ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'returns_iss', 'id_token_algorithms'],
            'auth_methods' => 3,
            'keys'         => 1,
        ];

        self::assertInstanceOf(ProposedOidcSettings::class, $proposed);
        self::assertSame($expected, $proposed->__debugInfo());
        self::assertSame($expected, $proposed->jsonSerialize());
        self::assertStringNotContainsString('op.example.test', (string) json_encode($proposed));
        self::assertSame(['kid', 'kty', 'alg'], array_keys($proposed->keys()[0]));

        foreach (self::dumps($proposed) as $dump) {
            self::assertStringNotContainsString('op.example.test', $dump);
            self::assertStringNotContainsString('rsa-1', $dump);
        }

        self::assertSame('Proposed settings cannot be serialised.', self::refusal(static fn (): string => serialize($proposed)));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Proposed settings cannot be unserialised.');

        $proposed->__unserialize([]);
    }

    /**
     * What a fetch read holds its values out of every dump, with the moment its
     * JWKS validated, and refuses to be serialised.
     *
     * @return void
     */
    public function testWhatAFetchReadHoldsItsValuesOutOfEveryDump(): void
    {
        $metadata = $this->importer()->fetch(self::ISSUER, null)->document();

        self::assertInstanceOf(OidcMetadata::class, $metadata);

        $expected = ['document' => '[redacted]', 'keys' => 1, 'keys_validated_at' => '2026-11-01T09:30:00+00:00'];

        self::assertSame($expected, $metadata->__debugInfo());
        self::assertSame($expected, $metadata->jsonSerialize());
        self::assertSame('rsa-1', $metadata->keys()->keys[0]->keyId());
        self::assertSame(self::ISSUER . '/jwks', $metadata->document()->jwksUri());

        foreach (self::dumps($metadata) as $dump) {
            self::assertStringNotContainsString('op.example.test', $dump);
            self::assertStringNotContainsString('rsa-1', $dump);
        }

        self::assertSame('OIDC metadata cannot be serialised.', self::refusal(static fn (): string => serialize($metadata)));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('OIDC metadata cannot be unserialised.');

        $metadata->__unserialize([]);
    }

    /**
     * The message of the `LogicException` the work throws, or none.
     *
     * @param  \Closure(): mixed  $work
     * @return ?string
     */
    private static function refusal(\Closure $work): ?string
    {
        try {
            $work();
        } catch (\LogicException $exception) {
            return $exception->getMessage();
        }

        return null;
    }

    /**
     * Each request made, as `[purpose, URL, cap]`.
     *
     * @return list<array{0: string, 1: string, 2: ?int}>
     */
    private function requests(): array
    {
        return array_map(static fn (FetchRequest $request): array => [$request->purpose->value, $request->url, $request->maxBytes], $this->fetcher->requests());
    }

    /**
     * The importer, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\DiscoveryImporter
     */
    private function importer(): DiscoveryImporter
    {
        return app(DiscoveryImporter::class);
    }

    /**
     * The members as JSON with a member the reader ignores padding it to
     * exactly the bytes given.
     *
     * @param  int  $bytes
     * @param  array<string, mixed>  $members
     * @return string
     */
    private static function paddedTo(int $bytes, array $members): string
    {
        $empty = (string) json_encode([...$members, 'pad' => ''], JSON_UNESCAPED_SLASHES);

        return (string) json_encode([...$members, 'pad' => str_repeat('x', $bytes - strlen($empty))], JSON_UNESCAPED_SLASHES);
    }

    /**
     * A JWKS of the number of keys given, one public key under as many `kid`s.
     *
     * @param  int  $count
     * @return string
     */
    private static function jwksOf(int $count): string
    {
        $keys = [];

        foreach (range(1, $count) as $number) {
            $keys[] = self::rsa()->jwk(null, 'sig', ['kid' => 'key-' . $number]);
        }

        return (string) json_encode(['keys' => $keys], JSON_UNESCAPED_SLASHES);
    }

    /**
     * The provider's RSA key, generated once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function rsa(): FakeSigningKey
    {
        return self::$rsa ??= FakeSigningKey::rsa();
    }

    /**
     * An elliptic curve key, generated once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function ec(): FakeSigningKey
    {
        return self::$ec ??= FakeSigningKey::ec();
    }
}
