<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Protocols\Enums\NavigationType;
use SineMacula\Laravel\Sso\Protocols\Oidc\AuthorizationRequests;
use SineMacula\Laravel\Sso\Protocols\Oidc\AuthorizationUrl;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\DumpsValues;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Feature tests for starting an OIDC authorisation code request (SSO-5.4,
 * SSO-5.5, SSO-7.1): the fields of the `Start` the start pipeline stores (the
 * expected issuer exactly, whether the provider must return `iss` both ways, no
 * SAML request id), the callback as the endpoint resolver built it and never
 * from the request, an endpoint whose query names a parameter the request sets
 * refused, a start without its values the pipeline's bug, and a navigation
 * whose every dump redacts every query value, with nothing logged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequests::class)]
#[CoversClass(AuthorizationUrl::class)]
final class AuthorizationRequestsTest extends TestCase
{
    use CapturesLogs, DumpsValues;

    /** @var string The connection's id. */
    private const string CONNECTION_ID = 'connection-1';

    /** @var string The issuer, whose trailing `/` is part of it. */
    private const string ISSUER = 'https://op.example.test/tenant/';

    /** @var string The authorisation endpoint. */
    private const string ENDPOINT = 'https://op.example.test/authorize';

    /** @var string The S256 challenge of the verifier the requests carry. */
    private const string CHALLENGE = 'tVEoG_h-ykFXVOswYJ0K41ihO_I7oRNIQlnQ4veUvA4';

    /** @var array<string, mixed> Complete settings. */
    private const array SETTINGS = [
        'issuer'                 => self::ISSUER,
        'authorization_endpoint' => self::ENDPOINT,
        'token_endpoint'         => 'https://op.example.test/token',
        'jwks_uri'               => 'https://op.example.test/jwks',
        'client_id'              => 'client-1',
    ];

    /**
     * Configure the endpoints, and capture what is logged.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.endpoints.base_url', 'https://api.example.com');

        $this->captureLogs();
    }

    /**
     * A start is a redirect to the authorisation endpoint with the request's
     * query, carrying the connection's callback as `redirect_uri`, and no SAML
     * request id.
     *
     * @return void
     */
    public function testAStartIsARedirectWithTheRequestsQuery(): void
    {
        $start = $this->start(self::SETTINGS);

        self::assertTrue($start->isNavigating());
        self::assertFalse($start->isRefused());
        self::assertNull($start->reason);
        self::assertNull($start->samlRequestId);
        self::assertSame(NavigationType::REDIRECT, $start->navigation?->type);
        self::assertSame([], $start->navigation->fields());
        self::assertSame(self::ENDPOINT . '?response_type=code'
            . '&client_id=client-1'
            . '&redirect_uri=https%3A%2F%2Fapi.example.com%2Fauth%2Fsso%2Fconnections%2Fconnection-1%2Fcallback'
            . '&scope=openid%20email%20profile'
            . '&state=the-state'
            . '&nonce=the-nonce'
            . '&code_challenge=' . self::CHALLENGE
            . '&code_challenge_method=S256', $start->navigation->url());
    }

    /**
     * The expected issuer is the connection's, exactly as configured: nothing
     * normalises it, the trailing `/` included.
     *
     * @return void
     */
    public function testTheExpectedIssuerIsExactlyTheConnections(): void
    {
        self::assertSame(self::ISSUER, $this->start(self::SETTINGS)->expectedIssuer);
    }

    /**
     * Rows of `[settings, whether the provider must return `iss`]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function provideReturnsIss(): iterable
    {
        yield from [
            'by default'           => [[], false],
            'when it does not'     => [['returns_iss' => false], false],
            'when it says it does' => [['returns_iss' => true], true],
        ];
    }

    /**
     * Whether the response must carry `iss` is what the connection says.
     *
     * @param  array<string, mixed>  $settings
     * @param  bool  $required
     * @return void
     */
    #[DataProvider('provideReturnsIss')]
    public function testIssuerRequiredIsWhatTheConnectionSays(array $settings, bool $required): void
    {
        $start = $this->start([...self::SETTINGS, ...$settings]);

        self::assertTrue($start->isNavigating());
        self::assertSame($required, $start->issuerRequired);
    }

    /**
     * The `redirect_uri` is exactly what the endpoint resolver answers for the
     * connection, whatever the request says its host is (SSO-5.5).
     *
     * @return void
     */
    public function testTheCallbackIsTheResolversNeverTheRequests(): void
    {
        $this->app?->instance('request', Request::create('https://evil.example/forged', 'GET', server: [
            'HTTP_HOST'             => 'evil.example',
            'HTTP_X_FORWARDED_HOST' => 'evil.example',
        ]));
        $this->app?->instance(EndpointResolver::class, new readonly class implements EndpointResolver {
            /**
             * Endpoints only this resolver would build, by the connection's id.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints
             */
            #[\Override]
            public function endpoints(SsoConnection $connection): ConnectionEndpoints
            {
                $url = 'https://own-layout.example/' . $connection->getConnectionId() . '/';

                return new ConnectionEndpoints($url . 'acs', $url . 'oidc?x=y', $url . 'entity', $url . 'metadata');
            }
        });

        $query = $this->queryOf($this->start(self::SETTINGS));

        self::assertSame('https://own-layout.example/connection-1/oidc?x=y', $query['redirect_uri'] ?? null);
    }

    /**
     * An authorisation endpoint whose own query names a parameter the request
     * sets is refused with `connection_unavailable` and nothing kept.
     *
     * @return void
     */
    public function testAnEndpointQueryNamingAParameterIsRefused(): void
    {
        $start = $this->start([...self::SETTINGS, 'authorization_endpoint' => self::ENDPOINT . '?State=x']);

        self::assertTrue($start->isRefused());
        self::assertFalse($start->isNavigating());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $start->reason);
        self::assertNull($start->navigation);
        self::assertNull($start->expectedIssuer);
        self::assertFalse($start->issuerRequired);
    }

    /**
     * An authorisation endpoint's own query is kept, and the request's follows.
     *
     * @return void
     */
    public function testAnEndpointsOwnQueryIsKept(): void
    {
        $start = $this->start([...self::SETTINGS, 'authorization_endpoint' => self::ENDPOINT . '?tenant=acme']);

        self::assertStringStartsWith(self::ENDPOINT . '?tenant=acme&response_type=code&client_id=client-1&', (string) $start->navigation?->url());
    }

    /**
     * Rows of `[purpose, the last parameters the request carries]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: string}>
     */
    public static function providePurposes(): iterable
    {
        yield from [
            'a sign in'          => [Purpose::SIGN_IN, '&code_challenge_method=S256'],
            'a link'             => [Purpose::LINK, '&code_challenge_method=S256'],
            'a reauthentication' => [Purpose::REAUTHENTICATE, '&code_challenge_method=S256&max_age=0&prompt=login'],
        ];
    }

    /**
     * The purpose the request names is what decides whether it forces fresh
     * authentication.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $last
     * @return void
     */
    #[DataProvider('providePurposes')]
    public function testThePurposeDecidesFreshAuthentication(Purpose $purpose, string $last): void
    {
        self::assertStringEndsWith($last, (string) $this->start(self::SETTINGS, $purpose)->navigation?->url());
    }

    /**
     * Rows of `[nonce, verifier]`: a start missing either.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideMissingValues(): iterable
    {
        yield from [
            'no nonce'    => [null, 'verifier-h'],
            'no verifier' => ['the-nonce', null],
            'neither'     => [null, null],
        ];
    }

    /**
     * A start without a nonce or a PKCE verifier is the pipeline's bug, never a
     * request without them.
     *
     * @param  ?string  $nonce
     * @param  ?string  $verifier
     * @return void
     */
    #[DataProvider('provideMissingValues')]
    public function testAStartWithoutItsValuesIsALogicException(?string $nonce, ?string $verifier): void
    {
        $connection = new IdentifiedConnection(self::CONNECTION_ID, settings: self::SETTINGS);
        $request    = new StartRequest(
            Purpose::SIGN_IN,
            'web',
            self::reference(),
            new Secret('the-state'),
            $nonce    === null ? null : new Secret($nonce),
            $verifier === null ? null : new Secret($verifier),
        );

        $this->expectException(\LogicException::class);

        $this->requests()->start($connection, OidcOptions::of($connection), $request);
    }

    /**
     * A connection with no authorisation endpoint is never started: only a
     * complete connection is, and asking anyway names the setting alone.
     *
     * @return void
     */
    public function testAnIncompleteConnectionIsALogicException(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The connection has no [authorization_endpoint]; only a complete connection is used.');

        $this->start(array_diff_key(self::SETTINGS, ['authorization_endpoint' => true]));
    }

    /**
     * Every dump of the navigation, and of the `Start` holding it, shows the
     * endpoint and the parameters' names, never a value, and the debug view is
     * exactly that URL. A start logs nothing.
     *
     * @return void
     */
    public function testEveryDumpRedactsEveryQueryValue(): void
    {
        $start = $this->start([...self::SETTINGS, 'max_age' => 600, 'extra_parameters' => ['login_hint' => 'person@example.test']]);

        self::assertSame([
            'type' => 'redirect',
            'url'  => self::ENDPOINT
                . '?response_type=[redacted]'
                . '&client_id=[redacted]'
                . '&redirect_uri=[redacted]'
                . '&scope=[redacted]'
                . '&state=[redacted]'
                . '&nonce=[redacted]'
                . '&code_challenge=[redacted]'
                . '&code_challenge_method=[redacted]'
                . '&max_age=[redacted]'
                . '&login_hint=[redacted]',
        ], $start->navigation?->__debugInfo());

        foreach ([$start->navigation, $start] as $value) {
            foreach (self::dumps($value) as $dumper => $dumped) {
                foreach (['the-state', 'the-nonce', 'verifier-h', self::CHALLENGE, 'client-1', 'person@example.test', 'api.example.com'] as $needle) {
                    self::assertStringNotContainsString($needle, $dumped, "{$dumper} shows [{$needle}].");
                }
            }
        }

        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * The query of the start's URL, as a provider reads it.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Start  $start
     * @return array<array-key, mixed>
     */
    private function queryOf(Start $start): array
    {
        parse_str((string) parse_url((string) $start->navigation?->url(), PHP_URL_QUERY), $query);

        return $query;
    }

    /**
     * Start a request through a connection with the settings.
     *
     * @param  array<string, mixed>  $settings
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     */
    private function start(array $settings, Purpose $purpose = Purpose::SIGN_IN): Start
    {
        $connection = new IdentifiedConnection(self::CONNECTION_ID, settings: $settings);
        $request    = new StartRequest($purpose, 'web', self::reference(), new Secret('the-state'), new Secret('the-nonce'), new Secret('verifier-h'));

        return $this->requests()->start($connection, OidcOptions::of($connection), $request);
    }

    /**
     * The collaborator, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\AuthorizationRequests
     */
    private function requests(): AuthorizationRequests
    {
        return app(AuthorizationRequests::class);
    }

    /**
     * A public reference, never sent.
     *
     * @return \SineMacula\Laravel\Sso\Flows\RequestReference
     */
    private static function reference(): RequestReference
    {
        return RequestReference::fromString('Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456');
    }
}
