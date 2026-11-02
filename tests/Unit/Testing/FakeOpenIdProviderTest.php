<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\JoseAdapter;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FrozenClock;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for the fake OpenID provider (SSO-12.4): its discovery document
 * and endpoints, its JWKS read when fetched (rotation, additions, removals),
 * the grant `authorize()` makes from the package's authorisation URL, its token
 * endpoint's strict client authentication and grant checks for each method, its
 * UserInfo endpoint, and the responses a test puts in place of each.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeOpenIdProvider::class)]
#[CoversClass(FakeTokenEndpoint::class)]
#[CoversClass(FakeAuthorization::class)]
final class FakeOpenIdProviderTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var string The redirect URI the authorisation requests name. */
    private const string CALLBACK = 'https://sso.example.test/auth/sso/connections/c1/callback';

    /** @var string The PKCE verifier the authorisation requests are made with. */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var string The S256 challenge of the verifier (RFC 7636 appendix B). */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var array<string, \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey> The keys, generated once. */
    private static array $keys = [];

    /**
     * The discovery document names the provider's endpoints under its issuer, a
     * trailing `/` removed, and the capabilities a strict provider has.
     *
     * @return void
     */
    public function testTheDiscoveryDocumentNamesItsEndpoints(): void
    {
        $provider = self::provider('https://op.example.test/tenant-1/');

        self::assertSame('https://op.example.test/tenant-1/.well-known/openid-configuration', $provider->discoveryUrl());
        $base = 'https://op.example.test/tenant-1';

        self::assertSame(
            [$base . '/authorize', $base . '/token', $base . '/userinfo', $base . '/jwks'],
            [$provider->endpoint('authorization'), $provider->endpoint('token'), $provider->endpoint('userinfo'), $provider->endpoint('jwks')],
        );

        $discovery = $provider->discovery();

        self::assertSame('https://op.example.test/tenant-1/', $discovery['issuer']);
        self::assertSame($provider->endpoint('jwks'), $discovery['jwks_uri']);
        self::assertSame(['code'], $discovery['response_types_supported']);
        self::assertSame(['S256'], $discovery['code_challenge_methods_supported']);
        self::assertTrue($discovery['authorization_response_iss_parameter_supported']);

        $this->expectExceptionObject(new \InvalidArgumentException('The fake provider has no [logout] endpoint.'));

        $provider->endpoint('logout');
    }

    /**
     * A test lays members over the discovery document, a `null` removing one.
     *
     * @return void
     */
    public function testTheDiscoveryDocumentTakesChanges(): void
    {
        $provider = self::provider()->withDiscovery(['issuer' => 'https://evil.example.test', 'authorization_response_iss_parameter_supported' => null]);
        $provider->withDiscovery(['jwks_uri' => 'http://op.example.test/jwks']);

        $discovery = $provider->discovery();

        self::assertSame(['https://evil.example.test', 'http://op.example.test/jwks'], [$discovery['issuer'], $discovery['jwks_uri']]);
        self::assertArrayNotHasKey('authorization_response_iss_parameter_supported', $discovery);
    }

    /**
     * The JWKS is read when it is fetched: a key added, removed or replaced
     * under its `kid` after one fetch is what the next sees.
     *
     * @return void
     */
    public function testTheJwksIsReadWhenFetched(): void
    {
        $fetcher  = new FakeFetcher;
        $provider = self::provider()->serve($fetcher);
        $kids     = static fn (): array => array_column(self::json($fetcher->fetch(FetchRequest::jwks($provider->endpoint('jwks'))))['keys'] ?? [], 'kid');

        self::assertSame(['rsa-1'], $kids());

        $provider->publish(self::key('rsa-2'), 'RS256');

        self::assertSame(['rsa-1', 'rsa-2'], $kids());

        $provider->unpublish('rsa-1')->publish(self::key('ec-1')->withKid('rsa-2'));

        self::assertSame(['rsa-2', 'rsa-2'], $kids());
        self::assertSame([self::key('rsa-2')->jwk('RS256'), self::key('ec-1')->withKid('rsa-2')->jwk()], $provider->jwks()['keys']);

        $provider->publishJwk(['kty' => 'oct', 'k' => 'c2VjcmV0'])->unpublish(null);

        self::assertSame(['rsa-2', 'rsa-2'], $kids());
    }

    /**
     * The discovery document is served as JSON, and a response a test gives an
     * endpoint is answered in its place until it is restored.
     *
     * @return void
     */
    public function testAnEndpointAnswersWhatATestGives(): void
    {
        $fetcher  = new FakeFetcher;
        $provider = self::provider()->serve($fetcher);
        $fetch    = static fn (): FetchResult => $fetcher->fetch(FetchRequest::discovery($provider->discoveryUrl()));

        self::assertSame([200, 'application/json', $provider->discovery()], [$fetch()->statusCode, $fetch()->header('content-type'), self::json($fetch())]);

        $provider->respond('discovery', FetchResult::failed());

        self::assertTrue($fetch()->reason !== null);

        $provider->respond('discovery', static fn (FetchRequest $request): FetchResult => FetchResult::fetched(500, [], $request->url));

        self::assertSame([500, $provider->discoveryUrl()], [$fetch()->statusCode, $fetch()->body()]);

        $provider->respond('discovery', null);

        self::assertSame(200, $fetch()->statusCode);
    }

    /**
     * A grant reads the authorisation URL's parameters and issues a code whose
     * ID token carries the nonce and the access token's `at_hash`, and a
     * callback query with the RFC 9207 `iss`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAGrantIsMadeFromTheAuthorizationUrl(): void
    {
        $provider      = self::provider();
        $authorization = $provider->authorize(self::authorizationUrl($provider));

        self::assertSame([
            'response_type'         => 'code',
            'client_id'             => 'fake-client',
            'redirect_uri'          => self::CALLBACK,
            'scope'                 => 'openid email',
            'state'                 => 'st',
            'nonce'                 => 'no',
            'code_challenge'        => self::CHALLENGE,
            'code_challenge_method' => 'S256',
        ], $authorization->parameters());
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $authorization->code);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $authorization->accessToken);
        self::assertInstanceOf(FakeIdToken::class, $authorization->idToken);

        $claims = $authorization->idToken->claims();

        self::assertSame(['no', 'fake-subject', 'fake-client'], [$claims['nonce'], $claims['sub'], $claims['aud']]);
        self::assertSame([1900000000, 1900000300, 1900000000], [$claims['iat'], $claims['exp'], $claims['auth_time']]);
        self::assertSame(JwsSigner::encode(substr(hash('sha256', $authorization->accessToken, true), 0, 16)), $claims['at_hash']);
        self::assertSame('code=' . $authorization->code . '&state=st&iss=https%3A%2F%2Fop.example.test', $authorization->query());
        self::assertSame('code=' . $authorization->code . '&state=other', $authorization->query(['state' => 'other', 'iss' => null]));
        self::assertSame('error=access_denied&error_description=No%20thanks&state=st&iss=https%3A%2F%2Fop.example.test', $authorization->errorQuery('access_denied', 'No thanks'));
        self::assertSame('error=login_required&state=st', $authorization->errorQuery('login_required', null, ['iss' => null]));
        self::assertSame('state=a&state=b&code%5B%5D=c', FakeAuthorization::repeated([['state', 'a'], ['state', 'b'], ['code[]', 'c']]));
        self::assertNull($authorization->parameter('prompt'));
    }

    /**
     * A tailor changes the ID token the code is answered with, or replaces it
     * with raw text.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATailorChangesTheIdToken(): void
    {
        $provider = self::provider();

        $changed = $provider->authorize(self::authorizationUrl($provider), static fn (FakeIdToken $token): FakeIdToken => $token->with('sub', 'someone'));
        $raw     = $provider->authorize(self::authorizationUrl($provider), static fn (): string => 'raw.token.text');

        self::assertSame('someone', $changed->idToken instanceof FakeIdToken ? $changed->idToken->claims()['sub'] : null);
        self::assertSame('raw.token.text', $raw->idToken);
    }

    /**
     * The token endpoint answers a code exchanged with `client_secret_basic`
     * once, with the ID token signed under the published key, the access token,
     * a refresh token and `Bearer`; the code is then used.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeIsExchangedOnce(): void
    {
        [$provider, $fetcher] = self::served();
        $authorization        = $provider->authorize(self::authorizationUrl($provider));
        $request              = self::tokenRequest($provider, $authorization, FetchCredentials::clientSecretBasic('fake-client', 'fake-secret'));

        $response = $fetcher->fetch($request);
        $body     = self::json($response);

        self::assertSame(200, $response->statusCode);
        self::assertSame(['access_token', 'token_type', 'expires_in', 'refresh_token', 'id_token', 'scope'], array_keys($body));
        self::assertSame([$authorization->accessToken, 'Bearer', 300, 'openid email'], [$body['access_token'], $body['token_type'], $body['expires_in'], $body['scope']]);
        self::assertIsString($body['id_token']);
        self::assertTrue(JwsSigner::verify($body['id_token'], $provider->signingKey()->publicKeyPem));
        self::assertSame('no-store', $response->header('cache-control'));
        self::assertSame(400, $fetcher->fetch(self::tokenRequest($provider, $authorization, FetchCredentials::clientSecretBasic('fake-client', 'fake-secret')))->statusCode);
    }

    /**
     * Each part of the grant that is wrong refuses the exchange with `400`
     * `invalid_grant`, and burns the code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAWrongGrantIsRefused(): void
    {
        [$provider, $fetcher] = self::served();
        $credentials          = static fn (): FetchCredentials => FetchCredentials::clientSecretBasic('fake-client', 'fake-secret');

        $changes = [['code_verifier' => 'wrong-verifier-wrong-verifier-wrong-verifier'], ['redirect_uri' => self::CALLBACK . '/'], ['grant_type' => 'refresh_token']];

        foreach ($changes as $change) {

            $authorization = $provider->authorize(self::authorizationUrl($provider));
            $response      = $fetcher->fetch(self::tokenRequest($provider, $authorization, $credentials(), $change));

            self::assertSame([400, 'invalid_grant'], [$response->statusCode, self::json($response)['error'] ?? null], (string) json_encode($change));
            self::assertSame(400, $fetcher->fetch(self::tokenRequest($provider, $authorization, $credentials()))->statusCode);
        }

        $unknown = $fetcher->fetch(self::tokenRequest($provider, $provider->authorize(self::authorizationUrl($provider)), $credentials(), ['code' => 'unknown']));

        self::assertSame([400, 'invalid_grant'], [$unknown->statusCode, self::json($unknown)['error'] ?? null]);
    }

    /**
     * The client must authenticate by exactly the registered method and secret:
     * anything else is `401` `invalid_client`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheClientMustAuthenticateByItsMethod(): void
    {
        [$provider, $fetcher] = self::served();
        $refused              = [
            FetchCredentials::clientSecretBasic('fake-client', 'wrong'),
            FetchCredentials::clientSecretBasic('other-client', 'fake-secret'),
            FetchCredentials::clientSecretPost('fake-client', 'fake-secret'),
        ];

        foreach ($refused as $credentials) {

            $response = $fetcher->fetch(self::tokenRequest($provider, $provider->authorize(self::authorizationUrl($provider)), $credentials));

            self::assertSame([401, 'invalid_client'], [$response->statusCode, self::json($response)['error'] ?? null]);
        }

        $provider->register('fake-client', 'client_secret_post', 'posted-secret');

        $posted = FetchCredentials::clientSecretPost('fake-client', 'posted-secret');

        self::assertSame(200, $fetcher->fetch(self::tokenRequest($provider, $provider->authorize(self::authorizationUrl($provider)), $posted))->statusCode);
        self::assertSame(401, $fetcher->fetch(FetchRequest::userInfo($provider->endpoint('token'), FetchCredentials::accessToken('abc')))->statusCode);
    }

    /**
     * A `private_key_jwt` client authenticates with an assertion the package
     * signs; one with another audience, another key, or a `jti` seen before is
     * refused.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAPrivateKeyJwtClientIsVerified(): void
    {
        [$provider, $fetcher] = self::served();
        $key                  = self::key('client');
        $now                  = CarbonImmutable::createFromTimestampUTC(1900000000);
        $assertion            = static fn (string $audience, FakeSigningKey $signer): string => (new JoseAdapter)
            ->signClientAssertion('fake-client', $audience, new Secret($signer->privateKeyPem), $now)
            ->reveal();
        $exchange = static fn (string $signed): int => (int) $fetcher
            ->fetch(self::tokenRequest($provider, $provider->authorize(self::authorizationUrl($provider)), FetchCredentials::privateKeyJwt('fake-client', $signed)))
            ->statusCode;

        $provider->register('fake-client', 'private_key_jwt', null, $key->publicKeyPem);

        $valid = $assertion($provider->endpoint('token'), $key);

        self::assertSame(200, $exchange($valid));
        self::assertSame(401, $exchange($valid));
        self::assertSame(401, $exchange($assertion($provider->endpoint('token') . '/', $key)));
        self::assertSame(401, $exchange($assertion($provider->endpoint('token'), self::key('rsa-2'))));
        self::assertSame(401, $exchange('not.an.assertion'));
    }

    /**
     * UserInfo answers an access token the token endpoint issued with its
     * claims and the subject of that code's ID token, and refuses any other.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testUserInfoAnswersAnIssuedAccessToken(): void
    {
        [$provider, $fetcher] = self::served();
        $tailor               = static fn (FakeIdToken $token): FakeIdToken => $token->with('sub', 'person-1');
        $authorization        = $provider->authorize(self::authorizationUrl($provider), $tailor);
        $endpoint             = $provider->endpoint('userinfo');
        $userInfo             = static fn (string $token): FetchResult => $fetcher->fetch(FetchRequest::userInfo($endpoint, FetchCredentials::accessToken($token)));

        self::assertSame(401, $userInfo($authorization->accessToken)->statusCode);

        $fetcher->fetch(self::tokenRequest($provider, $authorization, FetchCredentials::clientSecretBasic('fake-client', 'fake-secret')));

        $answered = self::json($userInfo($authorization->accessToken));

        self::assertSame(['sub' => 'person-1', 'email' => 'person@example.test', 'email_verified' => true, 'name' => 'Fake Person'], $answered);
        self::assertSame(401, $userInfo('another-token')->statusCode);

        $provider->withUserInfo(['sub' => 'someone-else', 'email_verified' => 'true']);

        self::assertSame(['sub' => 'someone-else', 'email_verified' => 'true'], self::json($userInfo($authorization->accessToken)));
    }

    /**
     * ID tokens are signed with the key and algorithm a test chooses, which is
     * not published by choosing it.
     *
     * @return void
     */
    public function testIdTokensAreSignedAsATestChooses(): void
    {
        $provider = self::provider()->signWith(self::key('ec-1'), 'ES256');
        $token    = (string) $provider->idToken(['sub' => 'x']);

        self::assertSame(self::key('ec-1'), $provider->signingKey());
        self::assertSame(['alg' => 'ES256', 'kid' => 'ec-1', 'typ' => 'JWT'], json_decode(JwsSigner::decode(explode('.', $token)[0]), true));
        self::assertTrue(JwsSigner::verify($token, self::key('ec-1')->publicKeyPem));
        self::assertSame(['rsa-1'], array_column($provider->jwks()['keys'], 'kid'));
        self::assertSame('x', $provider->idToken(['sub' => 'x'])->claims()['sub']);
    }

    /**
     * The discovery document is exactly this.
     *
     * @return void
     */
    public function testTheDiscoveryDocumentIsExact(): void
    {
        $provider = self::provider();

        self::assertSame([
            'issuer'                                           => FakeOpenIdProvider::ISSUER,
            'authorization_endpoint'                           => $provider->endpoint('authorization'),
            'token_endpoint'                                   => $provider->endpoint('token'),
            'userinfo_endpoint'                                => $provider->endpoint('userinfo'),
            'jwks_uri'                                         => $provider->endpoint('jwks'),
            'response_types_supported'                         => ['code'],
            'response_modes_supported'                         => ['query'],
            'grant_types_supported'                            => ['authorization_code'],
            'subject_types_supported'                          => ['public'],
            'id_token_signing_alg_values_supported'            => ['RS256', 'PS256', 'ES256'],
            'token_endpoint_auth_methods_supported'            => ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
            'token_endpoint_auth_signing_alg_values_supported' => ['PS256', 'ES256'],
            'code_challenge_methods_supported'                 => ['S256'],
            'scopes_supported'                                 => ['openid', 'email', 'profile'],
            'claims_supported'                                 => ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'email', 'email_verified', 'name'],
            'authorization_response_iss_parameter_supported'   => true,
        ], $provider->discovery());
    }

    /**
     * A key given is the provider's; with none, one is generated under `rsa-1`,
     * and the provider tells the time without a clock.
     *
     * @return void
     */
    public function testTheKeyAndTheClockDefault(): void
    {
        $before = time();
        $given  = new FakeOpenIdProvider(FakeOpenIdProvider::ISSUER, self::key('rsa-2'));
        $issued = (new FakeOpenIdProvider)->idToken()->claims()['iat'] ?? 0;

        self::assertSame('rsa-2', $given->idToken()->header()['kid'] ?? null);
        self::assertSame('rsa-1', (new FakeOpenIdProvider)->idToken()->header()['kid'] ?? null);
        self::assertGreaterThanOrEqual($before, $issued);
        self::assertLessThanOrEqual(time(), $issued);
    }

    /**
     * An ID token is exactly this, and a key with no `kid` names none.
     *
     * @return void
     */
    public function testAnIdTokenIsExact(): void
    {
        $token = self::provider()->idToken(['nonce' => 'n']);

        self::assertSame(['alg' => 'RS256', 'kid' => 'rsa-1', 'typ' => 'JWT'], $token->header());
        self::assertSame([
            'iss'       => FakeOpenIdProvider::ISSUER,
            'sub'       => FakeOpenIdProvider::SUBJECT,
            'aud'       => FakeOpenIdProvider::CLIENT_ID,
            'iat'       => 1900000000,
            'exp'       => 1900000300,
            'auth_time' => 1900000000,
            'nonce'     => 'n',
        ], $token->claims());

        $keyless = new FakeOpenIdProvider(FakeOpenIdProvider::ISSUER, self::key('rsa-1')->withKid(null));

        self::assertSame(['alg' => 'RS256', 'typ' => 'JWT'], $keyless->idToken()->header());
    }

    /**
     * Only what a request writes as a string is read from its URL, and a token
     * has no nonce when the request gave none.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAGrantReadsOnlyTheStringsOfItsUrl(): void
    {
        $provider = self::provider();
        $none     = $provider->authorize($provider->endpoint('authorization') . '?state=st');
        $listed   = $provider->authorize($provider->endpoint('authorization') . '?state[]=st&nonce[]=no');

        self::assertInstanceOf(FakeIdToken::class, $none->idToken);
        self::assertInstanceOf(FakeIdToken::class, $listed->idToken);
        self::assertArrayNotHasKey('nonce', $none->idToken->claims());
        self::assertArrayNotHasKey('nonce', $listed->idToken->claims());
        self::assertNull($listed->parameter('state'));
    }

    /**
     * The JWKS and UserInfo answer `200`; UserInfo with no credentials answers
     * exactly `invalid_token`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEndpointsAnswerExactly(): void
    {
        [$provider, $fetcher] = self::served();
        $authorization        = $provider->authorize(self::authorizationUrl($provider));

        $issued = $fetcher->fetch(self::tokenRequest($provider, $authorization, FetchCredentials::clientSecretBasic('fake-client', 'fake-secret')));
        $body   = self::json($issued);

        self::assertSame(
            ['Bearer', 300, 'fake-refresh-' . $authorization->code, 'openid email'],
            [$body['token_type'] ?? null, $body['expires_in'] ?? null, $body['refresh_token'] ?? null, $body['scope'] ?? null],
        );
        self::assertSame(200, $fetcher->fetch(FetchRequest::jwks($provider->endpoint('jwks')))->statusCode);
        self::assertSame(200, $fetcher->fetch(FetchRequest::userInfo($provider->endpoint('userinfo'), FetchCredentials::accessToken($authorization->accessToken)))->statusCode);

        $refused = FakeTokenEndpoint::json(401, ['error' => 'invalid_token']);
        $none    = $fetcher->fetch(FetchRequest::jwks($provider->endpoint('userinfo')));

        self::assertSame([$refused->statusCode, $refused->body()], [$none->statusCode, $none->body()]);
    }

    /**
     * A grant with no scope answers an empty one.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAGrantWithNoScopeAnswersAnEmptyOne(): void
    {
        [$provider, $fetcher] = self::served();

        $url           = $provider->endpoint('authorization') . '?' . http_build_query(['redirect_uri' => self::CALLBACK, 'code_challenge' => self::CHALLENGE, 'nonce' => 'no']);
        $authorization = $provider->authorize($url);
        $body          = self::json($fetcher->fetch(self::tokenRequest($provider, $authorization, FetchCredentials::clientSecretBasic('fake-client', 'fake-secret'))));

        self::assertSame('', $body['scope'] ?? null);
    }

    /**
     * Rows of `[changes to the claims, changes to the header, status]`: a
     * client assertion, at and past each thing it is held to.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: int}>
     */
    public static function provideAssertions(): iterable
    {
        $now = 1900000000;

        yield from [
            'valid'                 => [[], [], 200],
            'another issuer'        => [['iss' => 'someone'], [], 401],
            'another subject'       => [['sub' => 'someone'], [], 401],
            'neither its client'    => [['iss' => 'someone', 'sub' => 'someone'], [], 401],
            'another audience'      => [['aud' => 'https://other.example.test/token'], [], 401],
            'an empty jti'          => [['jti' => ''], [], 401],
            'a jti not a string'    => [['jti' => 7], [], 401],
            'no jti'                => [['jti' => null], [], 401],
            'no exp'                => [['exp' => null], [], 401],
            'no iat'                => [['iat' => null], [], 401],
            'exp at now'            => [['exp' => $now, 'iat' => $now - 1], [], 401],
            'exp a second on'       => [['exp' => $now + 1, 'iat' => $now], [], 200],
            'lives five minutes'    => [['exp' => $now + 300, 'iat' => $now], [], 200],
            'lives a second longer' => [['exp' => $now + 301, 'iat' => $now], [], 401],
            'typed otherwise'       => [[], ['typ' => 'at+jwt'], 401],
            'not typed'             => [[], ['typ' => null], 401],
            'a kid not a string'    => [[], ['kid' => 7], 401],
            'no kid'                => [[], ['kid' => null], 401],
        ];
    }

    /**
     * A client assertion is accepted only when every claim and header member is
     * what it is held to.
     *
     * @param  array<string, mixed>  $claims
     * @param  array<string, mixed>  $header
     * @param  int  $status
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideAssertions')]
    public function testAClientAssertionIsHeldToEveryMember(array $claims, array $header, int $status): void
    {
        [$provider, $fetcher] = self::served();
        $key                  = self::key('ec-client');
        $present              = static fn (mixed $value): bool => $value !== null;

        $provider->register('fake-client', 'private_key_jwt', null, $key->publicKeyPem);

        $assertion = JwsSigner::sign(
            array_filter([...['alg' => 'ES256', 'kid' => 'ec-client', 'typ' => 'JWT'], ...$header], $present),
            array_filter([...self::assertionClaims($provider), ...$claims], $present),
            $key,
        );
        $request = self::tokenRequest($provider, $provider->authorize(self::authorizationUrl($provider)), FetchCredentials::privateKeyJwt('fake-client', $assertion));

        self::assertSame($status, $fetcher->fetch($request)->statusCode);
    }

    /**
     * An assertion whose payload is no object is refused, and one refused does
     * not use up its `jti`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusedAssertionUsesNothingUp(): void
    {
        [$provider, $fetcher] = self::served();
        $key                  = self::key('ec-client');
        $claims               = self::assertionClaims($provider);
        $header               = ['alg' => 'ES256', 'kid' => 'ec-client', 'typ' => 'JWT'];
        $exchange             = static fn (string $assertion): int => (int) $fetcher
            ->fetch(self::tokenRequest($provider, $provider->authorize(self::authorizationUrl($provider)), FetchCredentials::privateKeyJwt('fake-client', $assertion)))
            ->statusCode;

        $provider->register('fake-client', 'private_key_jwt', null, $key->publicKeyPem);

        self::assertSame(401, $exchange(JwsSigner::sign($header, '"text"', $key)));
        self::assertSame(401, $exchange(JwsSigner::sign($header, [...$claims, 'aud' => 'elsewhere'], $key)));
        self::assertSame(200, $exchange(JwsSigner::sign($header, $claims, $key)));
        self::assertSame(401, $exchange(JwsSigner::sign($header, $claims, $key)));
    }

    /**
     * The claims of a client assertion valid at the provider's frozen now.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @return array<string, mixed>
     */
    private static function assertionClaims(FakeOpenIdProvider $provider): array
    {
        return ['iss' => 'fake-client', 'sub' => 'fake-client', 'aud' => $provider->endpoint('token'), 'jti' => 'a1', 'iat' => 1900000000, 'exp' => 1900000060];
    }

    /**
     * The JSON object a response's body holds.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @return array<array-key, mixed>
     */
    private static function json(FetchResult $response): array
    {
        $decoded = json_decode((string) $response->body(), true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * The token request the package would send for the grant, with the changes
     * laid over its form.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization  $authorization
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchCredentials  $credentials
     * @param  array<string, string>  $changes
     * @return \SineMacula\Laravel\Sso\Fetching\FetchRequest
     */
    private static function tokenRequest(FakeOpenIdProvider $provider, FakeAuthorization $authorization, FetchCredentials $credentials, array $changes = []): FetchRequest
    {
        $form = ['grant_type' => 'authorization_code', 'code' => $authorization->code, 'redirect_uri' => self::CALLBACK, 'code_verifier' => self::VERIFIER];

        return FetchRequest::token($provider->endpoint('token'), [...$form, ...$changes], $credentials);
    }

    /**
     * An authorisation URL as the package's start would make it.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @return string
     */
    private static function authorizationUrl(FakeOpenIdProvider $provider): string
    {
        return $provider->endpoint('authorization') . '?' . http_build_query([
            'response_type'         => 'code',
            'client_id'             => 'fake-client',
            'redirect_uri'          => self::CALLBACK,
            'scope'                 => 'openid email',
            'state'                 => 'st',
            'nonce'                 => 'no',
            'code_challenge'        => self::CHALLENGE,
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * A provider served on a fake fetcher.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider, 1: \SineMacula\Laravel\Sso\Testing\FakeFetcher}
     */
    private static function served(): array
    {
        $fetcher = new FakeFetcher;

        return [self::provider()->serve($fetcher), $fetcher];
    }

    /**
     * A provider at the issuer, with its key generated once and a frozen clock.
     *
     * @param  string  $issuer
     * @return \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider
     */
    private static function provider(string $issuer = FakeOpenIdProvider::ISSUER): FakeOpenIdProvider
    {
        return new FakeOpenIdProvider($issuer, self::key('rsa-1'), new FrozenClock(CarbonImmutable::createFromTimestampUTC(1900000000)));
    }

    /**
     * A key by its `kid`, generated once.
     *
     * @param  string  $kid
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(string $kid): FakeSigningKey
    {
        return self::$keys[$kid] ??= str_starts_with($kid, 'ec') ? FakeSigningKey::ec($kid) : FakeSigningKey::rsa($kid);
    }
}
