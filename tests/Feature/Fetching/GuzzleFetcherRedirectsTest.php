<?php

declare(strict_types = 1);

namespace Tests\Feature\Fetching;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\RequestInterface;
use SineMacula\Laravel\Sso\Fetching\AddressPolicy;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetcherSettings;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use Tests\Fixtures\Fetching\StubHostResolver;
use Tests\TestCase;

/**
 * Feature tests for the default fetcher's redirect handling. Nothing touches
 * the network.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuzzleFetcher::class)]
final class GuzzleFetcherRedirectsTest extends TestCase
{
    /** @var string The metadata URL fetched. */
    private const string URL = 'https://idp.example.com/metadata';

    /** @var array<string, list<string>> The hosts the stub resolver knows. */
    private const array HOSTS = [
        'idp.example.com'      => ['93.184.216.34'],
        'cdn.example.net'      => ['2606:4700:4700::1111'],
        'internal.example.net' => ['10.0.0.8'],
        'split.example.net'    => ['151.101.1.1', '127.0.0.1'],
    ];

    /** @var list<array{request: \Psr\Http\Message\RequestInterface, options: array<string, mixed>}> Every request the mock handler received, with its options. */
    private array $sent = [];

    /** @var \Monolog\Handler\TestHandler What the fetcher logged. */
    private TestHandler $log;

    /** @var \Tests\Fixtures\Fetching\StubHostResolver The resolver the fetcher asked. */
    private StubHostResolver $resolver;

    /**
     * Start each test with an empty log and a resolver that knows no host.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->log      = new TestHandler;
        $this->resolver = new StubHostResolver;
    }

    /**
     * Rows of `[status]`: the redirect statuses.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideRedirectStatuses(): iterable
    {
        yield from [
            'moved permanently'  => [301],
            'found'              => [302],
            'see other'          => [303],
            'temporary redirect' => [307],
            'permanent redirect' => [308],
        ];
    }

    /**
     * A redirect to another public `https` host is resolved, checked and pinned
     * again, and asked with `GET`.
     *
     * @param  int  $status
     * @return void
     */
    #[DataProvider('provideRedirectStatuses')]
    public function testFollowsARedirectRecheckedAndRepinned(int $status): void
    {
        $result = $this->fetcher([
            new Response($status, ['Location' => 'https://cdn.example.net/idp/metadata.xml']),
            new Response(200, ['Content-Type' => 'application/samlmetadata+xml'], '<EntityDescriptor/>'),
        ])->fetch(FetchRequest::metadata(self::URL));

        self::assertTrue($result->isFetched());
        self::assertSame(200, $result->statusCode);
        self::assertSame('<EntityDescriptor/>', $result->body());

        self::assertSame(['idp.example.com', 'cdn.example.net'], $this->resolver->lookups());
        self::assertCount(2, $this->sent);
        self::assertSame('https://cdn.example.net/idp/metadata.xml', (string) $this->sent[1]['request']->getUri());
        self::assertSame('GET', $this->sent[1]['request']->getMethod());
        self::assertSame(['idp.example.com:443:93.184.216.34'], $this->curlOptions(0)[CURLOPT_RESOLVE]);
        self::assertSame(['cdn.example.net:443:[2606:4700:4700::1111]'], $this->curlOptions(1)[CURLOPT_RESOLVE]);
        self::assertSame([], $this->log->getRecords());
    }

    /**
     * A followed redirect carries the purpose's headers and fixed options
     * again, and no body.
     *
     * @return void
     */
    public function testAFollowedRedirectIsSentLikeTheFirstRequest(): void
    {
        $this->fetcher([
            new Response(302, ['Location' => 'https://cdn.example.net/jwks']),
            new Response(200, [], '{"keys":[]}'),
        ])->fetch(FetchRequest::jwks(self::URL));

        $request = $this->sent[1]['request'];
        $options = $this->sent[1]['options'];

        self::assertSame('application/jwk-set+json, application/json;q=0.9', $request->getHeaderLine('Accept'));
        self::assertSame('laravel-sso', $request->getHeaderLine('User-Agent'));
        self::assertFalse($request->hasHeader('Authorization'));
        self::assertFalse($request->hasHeader('Cookie'));
        self::assertSame('', (string) $request->getBody());
        self::assertFalse($options['allow_redirects']);
        self::assertTrue($options['verify']);
        self::assertSame('', $options['proxy']);
    }

    /**
     * Rows of `[location, resolved]`: relative locations and what they resolve
     * to.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRelativeLocations(): iterable
    {
        yield from [
            'an absolute path' => ['/other/metadata?v=2', 'https://idp.example.com/other/metadata?v=2'],
            'a relative path'  => ['metadata.xml', 'https://idp.example.com/metadata.xml'],
            'a parent path'    => ['../up/metadata', 'https://idp.example.com/up/metadata'],
            'a network path'   => ['//cdn.example.net/metadata', 'https://cdn.example.net/metadata'],
            'a query only'     => ['?page=2', 'https://idp.example.com/metadata?page=2'],
        ];
    }

    /**
     * A relative `Location` resolves against the URL that answered and is
     * checked as usual.
     *
     * @param  string  $location
     * @param  string  $resolved
     * @return void
     */
    #[DataProvider('provideRelativeLocations')]
    public function testResolvesARelativeLocation(string $location, string $resolved): void
    {
        $result = $this->fetcher([
            new Response(302, ['Location' => $location]),
            new Response(200, [], 'ok'),
        ])->fetch(FetchRequest::metadata(self::URL));

        self::assertTrue($result->isFetched());
        self::assertSame($resolved, (string) $this->sent[1]['request']->getUri());
    }

    /**
     * Rows of `[location, cause]`: redirects the fetcher refuses, and why.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRefusedLocations(): iterable
    {
        yield from [
            'to http'             => ['http://cdn.example.net/metadata', 'scheme'],
            'to another scheme'   => ['file:///etc/passwd', 'malformed'],
            'with userinfo'       => ['https://user@cdn.example.net/metadata', 'userinfo'],
            'with a fragment'     => ['https://cdn.example.net/metadata#top', 'malformed'],
            'to a private host'   => ['https://internal.example.net/metadata', 'refused_address'],
            'to a split host'     => ['https://split.example.net/metadata', 'refused_address'],
            'to cloud metadata'   => ['https://169.254.169.254/latest/meta-data/', 'refused_address'],
            'to loopback ipv6'    => ['https://[::1]/', 'refused_address'],
            'to a decimal host'   => ['https://2130706433/', 'ip_form'],
            'to an octal host'    => ['https://0177.0.0.1/', 'ip_form'],
            'to a malformed host' => ['https://exa mple.com/', 'malformed'],
        ];
    }

    /**
     * A redirect to anything the fetcher refuses is refused, and the target is
     * never asked.
     *
     * @param  string  $location
     * @param  string  $cause
     * @return void
     */
    #[DataProvider('provideRefusedLocations')]
    public function testRefusesARedirectToWhatItWouldRefuse(string $location, string $cause): void
    {
        $result = $this->fetcher([new Response(302, ['Location' => $location])])->fetch(FetchRequest::discovery(self::URL));

        self::assertSame(FetchStatus::REFUSED, $result->status);
        self::assertCount(1, $this->sent);
        self::assertSame($cause, $this->loggedContext()['cause']);
        self::assertCount(1, $this->log->getRecords());
    }

    /**
     * A redirect to a host that resolves to nothing fails, with the target
     * never asked.
     *
     * @return void
     */
    public function testARedirectToAnUnresolvableHostFails(): void
    {
        $result = $this->fetcher([new Response(302, ['Location' => 'https://nowhere.example.net/'])])->fetch(FetchRequest::metadata(self::URL));

        self::assertSame(FetchStatus::FAILED, $result->status);
        self::assertCount(1, $this->sent);
        self::assertSame('unresolved', $this->loggedContext()['cause']);
    }

    /**
     * More redirects than the limit fail; exactly the limit is followed.
     *
     * @return void
     */
    public function testFailsPastTheRedirectLimit(): void
    {
        config()->set('sso.fetcher.max_redirects', 2);

        $redirect = static fn (int $hop): Response => new Response(302, ['Location' => 'https://idp.example.com/hop/' . $hop]);

        $failed = $this->fetcher([$redirect(1), $redirect(2), $redirect(3)])->fetch(FetchRequest::metadata(self::URL));

        self::assertSame(FetchStatus::FAILED, $failed->status);
        self::assertCount(3, $this->sent);
        self::assertSame('too_many_redirects', $this->loggedContext()['cause']);

        $fetched = $this->fetcher([$redirect(1), $redirect(2), new Response(200, [], 'ok')])->fetch(FetchRequest::metadata(self::URL));

        self::assertTrue($fetched->isFetched());
        self::assertCount(3, $this->sent);
        self::assertSame('https://idp.example.com/hop/2', (string) $this->sent[2]['request']->getUri());
    }

    /**
     * With no redirects allowed, the first redirect fails and nothing more is
     * asked.
     *
     * @return void
     */
    public function testFollowsNothingWhenNoRedirectIsAllowed(): void
    {
        config()->set('sso.fetcher.max_redirects', 0);

        $result = $this->fetcher([new Response(302, ['Location' => 'https://cdn.example.net/'])])->fetch(FetchRequest::metadata(self::URL));

        self::assertSame(FetchStatus::FAILED, $result->status);
        self::assertCount(1, $this->sent);
        self::assertSame(['idp.example.com'], $this->resolver->lookups());
    }

    /**
     * Rows of `[request]`: requests that carry a credential.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchRequest}>
     */
    public static function provideCredentialedRequests(): iterable
    {
        $form = ['grant_type' => 'authorization_code', 'code' => 'the-code'];

        yield from [
            'a token request, basic' => [FetchRequest::token(self::URL, $form, FetchCredentials::clientSecretBasic('client', 'the-secret'))],
            'a token request, post'  => [FetchRequest::token(self::URL, $form, FetchCredentials::clientSecretPost('client', 'the-secret'))],
            'a token request, jwt'   => [FetchRequest::token(self::URL, $form, FetchCredentials::privateKeyJwt('client', 'header.payload.signature'))],
            'a userinfo request'     => [FetchRequest::userInfo(self::URL, FetchCredentials::accessToken('the-access-token'))],
        ];
    }

    /**
     * A credentialed request answered with a redirect is refused, so the
     * credential is never sent on.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @return void
     */
    #[DataProvider('provideCredentialedRequests')]
    public function testACredentialedRequestFollowsNoRedirect(FetchRequest $request): void
    {
        $result = $this->fetcher([new Response(302, ['Location' => 'https://cdn.example.net/token'])])->fetch($request);

        self::assertSame(FetchStatus::REFUSED, $result->status);
        self::assertCount(1, $this->sent);
        self::assertSame(['idp.example.com'], $this->resolver->lookups());
        self::assertSame('redirect_refused', $this->loggedContext()['cause']);
        self::assertSame($request->purpose->value, $this->loggedContext()['purpose']);
    }

    /**
     * A `3xx` without `Location`, or `Location` on another status, is fetched
     * and not followed.
     *
     * @return void
     */
    public function testAResponseThatIsNotARedirectIsNotFollowed(): void
    {
        $notModified = $this->fetcher([new Response(304)])->fetch(FetchRequest::metadata(self::URL));

        self::assertTrue($notModified->isFetched());
        self::assertSame(304, $notModified->statusCode);
        self::assertCount(1, $this->sent);

        $created = $this->fetcher([new Response(201, ['Location' => 'https://cdn.example.net/'])])->fetch(FetchRequest::metadata(self::URL));

        self::assertTrue($created->isFetched());
        self::assertSame(201, $created->statusCode);
        self::assertCount(1, $this->sent);
    }

    /**
     * Any `3xx` with a `Location` is followed, `300 Multiple Choices` too.
     *
     * @return void
     */
    public function testAnyRedirectStatusWithALocationIsFollowed(): void
    {
        $multipleChoices = $this->fetcher([
            new Response(300, ['Location' => 'https://cdn.example.net/']),
            new Response(200, [], 'followed'),
        ])->fetch(FetchRequest::metadata(self::URL));

        self::assertSame('followed', $multipleChoices->body());
        self::assertCount(2, $this->sent);
    }

    /**
     * A credentialed request answered with a `3xx` without `Location` is
     * fetched.
     *
     * @return void
     */
    public function testACredentialedResponseWithoutLocationIsFetched(): void
    {
        $result = $this->fetcher([new Response(304)])->fetch(FetchRequest::userInfo(self::URL, FetchCredentials::accessToken('the-access-token')));

        self::assertTrue($result->isFetched());
        self::assertSame(304, $result->statusCode);
        self::assertSame([], $this->log->getRecords());
    }

    /**
     * A fetcher over a mock handler, the stub resolver of the known hosts and a
     * capturing logger.
     *
     * @param  list<\Psr\Http\Message\ResponseInterface|\Throwable>  $responses
     * @return \SineMacula\Laravel\Sso\Fetching\GuzzleFetcher
     */
    private function fetcher(array $responses): GuzzleFetcher
    {
        $mock = new MockHandler($responses);

        $this->sent     = [];
        $this->log      = new TestHandler;
        $this->resolver = new StubHostResolver(self::HOSTS);

        $handler = function (RequestInterface $request, array $options) use ($mock): PromiseInterface {
            $this->sent[] = ['request' => $request, 'options' => $options];

            return $mock($request, $options);
        };

        $settings = new FetcherSettings(config());

        return new GuzzleFetcher($settings, new AddressPolicy($settings), new Logger('sso', [$this->log]), $this->resolver, $handler);
    }

    /**
     * The cURL options the mock handler received at the index.
     *
     * @param  int  $index
     * @return array<int, mixed>
     */
    private function curlOptions(int $index): array
    {
        $curl = $this->sent[$index]['options']['curl'] ?? null;

        self::assertIsArray($curl);

        /** @var array<int, mixed> $curl */
        return $curl;
    }

    /**
     * The context of the last warning logged.
     *
     * @return array<string, mixed>
     */
    private function loggedContext(): array
    {
        $records = $this->log->getRecords();

        self::assertNotSame([], $records);

        return $records[array_key_last($records)]->context;
    }
}
