<?php

declare(strict_types = 1);

namespace Tests\Feature\Fetching;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\RequestInterface;
use SineMacula\Laravel\Sso\Fetching\AddressPolicy;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetcherSettings;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use Tests\Fixtures\Fetching\StubHostResolver;
use Tests\TestCase;

/**
 * Feature tests for the credentials the default fetcher sends by purpose: none
 * to metadata, discovery or a JWKS; exactly one client authentication, as its
 * kind says, to a token endpoint, with the caller's form form-encoded; and only
 * the access token to UserInfo (SSO-2.9, SSO-7.2, RFC 6749 §2.3.1, RFC 7523,
 * RFC 6750). Nothing touches the network.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuzzleFetcher::class)]
final class GuzzleFetcherCredentialsTest extends TestCase
{
    /** @var string The token endpoint. */
    private const string URL = 'https://idp.example.com/oauth/token';

    /** @var string A signed client assertion, in shape only. */
    private const string ASSERTION = 'header.payload.signature';

    /** @var array<string, string> A token request's form, as the caller gives it. */
    private const array FORM = [
        'grant_type'    => 'authorization_code',
        'code'          => 'a b&c=d',
        'redirect_uri'  => 'https://api.example.com/auth/sso/connections/7/callback',
        'code_verifier' => 'v~e.r_i-f',
    ];

    /** @var string The caller's form, form-encoded (RFC 1738: a space as `+`, `~` encoded). */
    private const string ENCODED_FORM = 'grant_type=authorization_code&code=a+b%26c%3Dd'
        . '&redirect_uri=https%3A%2F%2Fapi.example.com%2Fauth%2Fsso%2Fconnections%2F7%2Fcallback&code_verifier=v%7Ee.r_i-f';

    /** @var list<string> The headers a request may carry besides its credential and body type. */
    private const array ALLOWED_HEADERS = ['accept', 'user-agent', 'host', 'content-length'];

    /** @var list<array{request: \Psr\Http\Message\RequestInterface, options: array<string, mixed>}> Every request the mock handler received, with its options. */
    private array $sent = [];

    /**
     * `client_secret_basic` sends the client id and secret in the
     * `Authorization: Basic` header, as RFC 6749 §2.3.1's example gives it, and
     * nothing of them in the body.
     *
     * @return void
     */
    public function testSendsClientSecretBasicAsRfc6749Gives(): void
    {
        $this->fetch(FetchRequest::token(self::URL, self::FORM, FetchCredentials::clientSecretBasic('s6BhdRkqt3', '7Fjfp0ZBr1KtDRbnfVdmIw')));

        $request = $this->sentRequest();

        self::assertSame('Basic ' . base64_encode('s6BhdRkqt3:7Fjfp0ZBr1KtDRbnfVdmIw'), $request->getHeaderLine('Authorization'));
        self::assertSame(self::ENCODED_FORM, (string) $request->getBody());
    }

    /**
     * `client_secret_basic` form-encodes the client id and secret before
     * joining and encoding them, so a colon, space, plus, percent or non-ASCII
     * character in either cannot be misread.
     *
     * @return void
     */
    public function testFormEncodesTheBasicClientIdAndSecret(): void
    {
        $this->fetch(FetchRequest::token(self::URL, self::FORM, FetchCredentials::clientSecretBasic('client id:é/+', 'p@ss w:rd&=%')));

        self::assertSame('Basic ' . base64_encode('client+id%3A%C3%A9%2F%2B:p%40ss+w%3Ard%26%3D%25'), $this->sentRequest()->getHeaderLine('Authorization'));
    }

    /**
     * `client_secret_post` sends the client id and secret in the body, after
     * the caller's form, and no `Authorization` header.
     *
     * @return void
     */
    public function testSendsClientSecretPostInTheBody(): void
    {
        $this->fetch(FetchRequest::token(self::URL, self::FORM, FetchCredentials::clientSecretPost('client id', 'the secret&')));

        $request = $this->sentRequest();

        self::assertFalse($request->hasHeader('Authorization'));
        self::assertSame(self::ENCODED_FORM . '&client_id=client+id&client_secret=the+secret%26', (string) $request->getBody());
    }

    /**
     * `private_key_jwt` sends the client id, the assertion type and the signed
     * assertion in the body, and no `Authorization` header or secret.
     *
     * @return void
     */
    public function testSendsPrivateKeyJwtInTheBody(): void
    {
        $this->fetch(FetchRequest::token(self::URL, self::FORM, FetchCredentials::privateKeyJwt('client-1', self::ASSERTION)));

        $request = $this->sentRequest();

        self::assertFalse($request->hasHeader('Authorization'));
        self::assertSame(
            self::ENCODED_FORM . '&client_id=client-1&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=' . self::ASSERTION,
            (string) $request->getBody(),
        );
    }

    /**
     * A token request is a form-encoded `POST` of the caller's fields.
     *
     * @return void
     */
    public function testPostsTheTokenRequestFormEncoded(): void
    {
        $this->fetch(FetchRequest::token(self::URL, self::FORM, FetchCredentials::clientSecretBasic('client', 'secret')));

        $request = $this->sentRequest();

        self::assertSame('POST', $request->getMethod());
        self::assertSame('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        self::assertSame(self::URL, (string) $request->getUri());

        parse_str((string) $request->getBody(), $fields);

        self::assertSame(self::FORM, $fields);
    }

    /**
     * UserInfo carries the access token in the `Authorization: Bearer` header
     * alone: a `GET`, with no body and no body type.
     *
     * @return void
     */
    public function testSendsTheAccessTokenToUserInfoOnly(): void
    {
        $this->fetch(FetchRequest::userInfo('https://idp.example.com/userinfo', FetchCredentials::accessToken('the.access.token')));

        $request = $this->sentRequest();

        self::assertSame('GET', $request->getMethod());
        self::assertSame('Bearer the.access.token', $request->getHeaderLine('Authorization'));
        self::assertSame('', (string) $request->getBody());
        self::assertFalse($request->hasHeader('Content-Type'));
        self::assertSame([], array_values(array_diff(self::headerNames($request), [...self::ALLOWED_HEADERS, 'authorization'])));
    }

    /**
     * Rows of `[request]`: requests that carry no credential.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchRequest}>
     */
    public static function provideUncredentialedRequests(): iterable
    {
        yield from [
            'metadata'  => [FetchRequest::metadata('https://idp.example.com/metadata')],
            'discovery' => [FetchRequest::discovery('https://idp.example.com/.well-known/openid-configuration')],
            'jwks'      => [FetchRequest::jwks('https://idp.example.com/jwks')],
        ];
    }

    /**
     * Metadata, discovery and a JWKS carry no `Authorization` header, cookie or
     * body: a bare `GET`.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @return void
     */
    #[DataProvider('provideUncredentialedRequests')]
    public function testSendsNoCredentialWithoutOne(FetchRequest $request): void
    {
        $this->fetch($request);

        $sent = $this->sentRequest();

        self::assertSame('GET', $sent->getMethod());
        self::assertFalse($sent->hasHeader('Authorization'));
        self::assertSame('', (string) $sent->getBody());
        self::assertSame([], array_values(array_diff(self::headerNames($sent), self::ALLOWED_HEADERS)));
    }

    /**
     * Rows of `[credentials, header, body fields]`: each client authentication
     * and where it puts itself.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchCredentials, 1: bool, 2: list<string>}>
     */
    public static function provideClientAuthentications(): iterable
    {
        yield from [
            'client_secret_basic' => [FetchCredentials::clientSecretBasic('client', 'secret'), true, []],
            'client_secret_post'  => [FetchCredentials::clientSecretPost('client', 'secret'), false, ['client_id', 'client_secret']],
            'private_key_jwt'     => [FetchCredentials::privateKeyJwt('client', self::ASSERTION), false, ['client_id', 'client_assertion_type', 'client_assertion']],
        ];
    }

    /**
     * Exactly one client authentication is present: the `Authorization` header
     * or the body's client fields, never both, never another, and no header
     * beyond those every request carries and the body's type.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchCredentials  $credentials
     * @param  bool  $header
     * @param  list<string>  $fields
     * @return void
     */
    #[DataProvider('provideClientAuthentications')]
    public function testSendsExactlyOneClientAuthentication(FetchCredentials $credentials, bool $header, array $fields): void
    {
        $this->fetch(FetchRequest::token(self::URL, self::FORM, $credentials));

        $request = $this->sentRequest();

        parse_str((string) $request->getBody(), $body);

        self::assertSame($header, $request->hasHeader('Authorization'));
        self::assertCount($header ? 1 : 0, $request->getHeader('Authorization'));
        self::assertSame([...array_keys(self::FORM), ...$fields], array_keys($body));
        self::assertSame([], array_values(array_diff(self::headerNames($request), [...self::ALLOWED_HEADERS, 'content-type', 'authorization'])));
    }

    /**
     * A token request with an empty form is still a form-encoded `POST`.
     *
     * @return void
     */
    public function testATokenRequestWithAnEmptyForm(): void
    {
        $this->fetch(FetchRequest::token(self::URL, [], FetchCredentials::clientSecretBasic('client', 'secret')));

        self::assertSame('POST', $this->sentRequest()->getMethod());
        self::assertSame('', (string) $this->sentRequest()->getBody());
        self::assertSame('application/x-www-form-urlencoded', $this->sentRequest()->getHeaderLine('Content-Type'));
    }

    /**
     * Fetch the request through a mock handler answering `200`, capturing what
     * it sent.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @return void
     */
    private function fetch(FetchRequest $request): void
    {
        $mock = new MockHandler([new Response(200, [], '{}')]);

        $this->sent = [];

        $handler = function (RequestInterface $request, array $options) use ($mock): PromiseInterface {
            $this->sent[] = ['request' => $request, 'options' => $options];

            return $mock($request, $options);
        };

        $settings = new FetcherSettings(config());
        $fetcher  = new GuzzleFetcher($settings, new AddressPolicy($settings), new Logger('sso'), new StubHostResolver(['idp.example.com' => ['93.184.216.34']]), $handler);

        self::assertTrue($fetcher->fetch($request)->isFetched());
    }

    /**
     * The one request the mock handler received.
     *
     * @return \Psr\Http\Message\RequestInterface
     */
    private function sentRequest(): RequestInterface
    {
        self::assertCount(1, $this->sent);

        return $this->sent[0]['request'];
    }

    /**
     * The request's header names, in lower case.
     *
     * @param  \Psr\Http\Message\RequestInterface  $request
     * @return list<string>
     */
    private static function headerNames(RequestInterface $request): array
    {
        return array_map(static fn (int|string $name): string => strtolower((string) $name), array_keys($request->getHeaders()));
    }
}
