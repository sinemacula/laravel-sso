<?php

declare(strict_types = 1);

namespace Tests\Feature\Fetching;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamInterface;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\AddressPolicy;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetcherSettings;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use Tests\Fixtures\Fetching\StubHostResolver;
use Tests\TestCase;

/**
 * Feature tests for the default fetcher's checks and transport options: only
 * `https`, no userinfo, fragment or ambiguous host, no IP literal written any
 * way but canonically, no refused address however the host resolves, the
 * checked address pinned, the transport options fixed, the size cap, failures
 * and refusals as reason codes, and one warning each with nothing of the
 * request or response in it (SSO-2.9). Every request goes to a mock handler and
 * every name to a stub resolver: nothing touches the network.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuzzleFetcher::class)]
final class GuzzleFetcherTest extends TestCase
{
    /** @var string The identity provider's host in the tests. */
    private const string HOST = 'idp.example.com';

    /** @var string The public address the host resolves to. */
    private const string ADDRESS = '93.184.216.34';

    /** @var string The metadata URL fetched by default. */
    private const string URL = 'https://idp.example.com/metadata';

    /** @var list<string> The context keys a warning may carry. */
    private const array LOGGED_KEYS = ['purpose', 'reason', 'cause', 'host', 'exception_class'];

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
     * Rows of `[url]`: URLs whose scheme is not `https`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOtherSchemes(): iterable
    {
        yield from [
            'http'                => ['http://idp.example.com/metadata'],
            'ftp'                 => ['ftp://idp.example.com/metadata'],
            'file'                => ['file:///etc/passwd'],
            'gopher'              => ['gopher://idp.example.com:70/'],
            'no scheme'           => ['//idp.example.com/metadata'],
            'a bare host'         => ['idp.example.com/metadata'],
            'https without slash' => ['https:idp.example.com/metadata'],
        ];
    }

    /**
     * A URL that is not `https` is refused before anything is resolved or sent.
     *
     * @param  string  $url
     * @return void
     */
    #[DataProvider('provideOtherSchemes')]
    public function testRefusesAnythingButHttps(string $url): void
    {
        $result = $this->fetcher()->fetch(FetchRequest::metadata($url));

        $this->assertRefusedBeforeSending($result);
    }

    /**
     * The scheme is compared without regard to case, as the host is normalised.
     *
     * @return void
     */
    public function testAcceptsHttpsInAnyCase(): void
    {
        $result = $this->fetcher([new Response(200, [], 'ok')])->fetch(FetchRequest::metadata('HTTPS://IDP.EXAMPLE.COM/metadata'));

        self::assertTrue($result->isFetched());
        self::assertSame(self::URL, (string) $this->sentRequest()->getUri());
    }

    /**
     * Rows of `[url]`: URLs carrying userinfo.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUserinfo(): iterable
    {
        yield from [
            'a user and password' => ['https://user:pass@idp.example.com/metadata'],
            'a user'              => ['https://user@idp.example.com/metadata'],
            'an empty user'       => ['https://@idp.example.com/metadata'],
            'a host-like user'    => ['https://idp.example.com@169.254.169.254/metadata'],
            'a host and port'     => ['https://idp.example.com:443@evil.example.net/metadata'],
        ];
    }

    /**
     * A URL carrying userinfo is refused, so nothing in it can be read as
     * another host or as a credential.
     *
     * @param  string  $url
     * @return void
     */
    #[DataProvider('provideUserinfo')]
    public function testRefusesUserinfo(string $url): void
    {
        $result = $this->fetcher()->fetch(FetchRequest::metadata($url));

        $this->assertRefusedBeforeSending($result);
        self::assertSame('userinfo', $this->loggedContext()['cause']);
    }

    /**
     * Rows of `[url]`: URLs that cannot be read one way only.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedUrls(): iterable
    {
        yield from [
            'a fragment'               => ['https://idp.example.com/metadata#section'],
            'an empty fragment'        => ['https://idp.example.com/metadata#'],
            'a fragment hiding a host' => ['https://idp.example.com#@evil.example.net/'],
            'no host'                  => ['https:///metadata'],
            'nothing after scheme'     => ['https://'],
            'a backslash'              => ['https://idp.example.com\@evil.example.net/'],
            'a space'                  => ['https://idp.example.com /metadata'],
            'a tab'                    => ["https://idp.example.com\t/metadata"],
            'a newline'                => ["https://idp.example.com/metadata\nHost: evil"],
            'a null byte'              => ["https://idp.example.com\0.evil.example.net/"],
            'port zero'                => ['https://idp.example.com:0/metadata'],
            'port out of range'        => ['https://idp.example.com:65536/metadata'],
            'a percent-encoded host'   => ['https://idp%2eexample.com/metadata'],
            'invalid punycode'         => ['https://xn--zz.example.com/metadata'],
            'an empty label'           => ['https://idp..example.com/metadata'],
            'only a dot'               => ['https://./metadata'],
            'two trailing dots'        => ['https://idp.example.com../metadata'],
            'an unclosed bracket'      => ['https://[2606:4700:4700::1111/metadata'],
            'a host too long'          => ['https://' . str_repeat('a.', 127) . 'example.com/'],
            'a fullwidth colon'        => ['https://ｉｄｐ.example.com：８０８０/metadata'],
            'a fullwidth at sign'      => ['https://evil.example＠idp.example.com/metadata'],
            'a fullwidth slash'        => ['https://evil.example／x.idp.example.com/metadata'],
            'an idn host and userinfo' => ['https://user@bücher.example/metadata'],
            'an idn bracketed host'    => ['https://[bücher.example]/metadata'],
        ];
    }

    /**
     * A URL that is malformed or ambiguous (a fragment, no host, a character
     * parsers disagree on, an impossible port or host) is refused before
     * anything is resolved or sent.
     *
     * @param  string  $url
     * @return void
     */
    #[DataProvider('provideMalformedUrls')]
    public function testRefusesAMalformedUrl(string $url): void
    {
        $result = $this->fetcher()->fetch(FetchRequest::metadata($url));

        $this->assertRefusedBeforeSending($result);
    }

    /**
     * Rows of `[url]`: hosts that a parser may read as an IPv4 address but are
     * not a canonical dotted quad, and IPv6 literals not written canonically.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideIpForms(): iterable
    {
        yield from [
            'decimal'               => ['https://2130706433/'],
            'octal'                 => ['https://0177.0.0.1/'],
            'octal, whole'          => ['https://017700000001/'],
            'hex'                   => ['https://0x7f.1/'],
            'hex, whole'            => ['https://0x7f000001/'],
            'hex, dotted'           => ['https://0x7F.0x0.0x0.0x1/'],
            'short, two parts'      => ['https://127.1/'],
            'short, three parts'    => ['https://127.0.1/'],
            'a leading zero'        => ['https://127.0.0.01/'],
            'a public leading zero' => ['https://8.8.8.010/'],
            'too many parts'        => ['https://1.2.3.4.5/'],
            'out of range'          => ['https://256.0.0.1/'],
            'a numeric last label'  => ['https://idp.example.123/'],
            'a hex last label'      => ['https://idp.example.0x1/'],
            'decimal metadata'      => ['https://2852039166/latest/meta-data/'],
            'ipv6 uncompressed'     => ['https://[0:0:0:0:0:0:0:1]/'],
            'ipv6 padded'           => ['https://[2606:4700:4700:0000::1111]/'],
            'ipv6 mapped as hex'    => ['https://[::ffff:7f00:1]/'],
            'ipv6 with a zone'      => ['https://[fe80::1%25eth0]/'],
            'ipv6 not an address'   => ['https://[idp.example.com]/'],
            'fullwidth decimal'     => ['https://２１３０７０６４３３/'],
        ];
    }

    /**
     * An IP literal written any way but canonically is refused before anything
     * is resolved or sent, so no parser downstream can read it as an address
     * the check did not see.
     *
     * @param  string  $url
     * @return void
     */
    #[DataProvider('provideIpForms')]
    public function testRefusesEveryNonCanonicalIpForm(string $url): void
    {
        $result = $this->fetcher()->fetch(FetchRequest::metadata($url));

        $this->assertRefusedBeforeSending($result);
        self::assertSame('ip_form', $this->loggedContext()['cause']);
    }

    /**
     * Rows of `[url]`: canonical IP literals of refused addresses.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedLiterals(): iterable
    {
        yield from [
            'ipv6 loopback'        => ['https://[::1]/'],
            'ipv4-mapped loopback' => ['https://[::ffff:127.0.0.1]/'],
            'cloud metadata'       => ['https://169.254.169.254/latest/meta-data/'],
            'ipv4 loopback'        => ['https://127.0.0.1/'],
            'private'              => ['https://10.0.0.1/'],
            'unique local'         => ['https://[fd00:ec2::254]/'],
            'fullwidth loopback'   => ['https://１２７.０.０.１/'],
        ];
    }

    /**
     * A refused address given as a literal is refused without asking the
     * resolver or sending anything.
     *
     * @param  string  $url
     * @return void
     */
    #[DataProvider('provideRefusedLiterals')]
    public function testRefusesARefusedAddressGivenAsALiteral(string $url): void
    {
        $result = $this->fetcher()->fetch(FetchRequest::metadata($url));

        $this->assertRefusedBeforeSending($result);
        self::assertSame('refused_address', $this->loggedContext()['cause']);
    }

    /**
     * Rows of `[addresses]`: answers that hold at least one refused address.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideSplitAnswers(): iterable
    {
        yield from [
            'public then private'     => [[self::ADDRESS, '10.0.0.5']],
            'private then public'     => [['10.0.0.5', self::ADDRESS]],
            'public then loopback v6' => [[self::ADDRESS, '::1']],
            'public then metadata'    => [['2606:4700:4700::1111', '169.254.169.254']],
            'only private'            => [['192.168.1.1']],
            'public then garbage'     => [[self::ADDRESS, 'not-an-address']],
        ];
    }

    /**
     * A host resolving to any refused address is refused, whatever else it
     * resolves to and in whatever order, so a split answer cannot slip a
     * private address through; nothing is sent.
     *
     * @param  list<string>  $addresses
     * @return void
     */
    #[DataProvider('provideSplitAnswers')]
    public function testRefusesAHostResolvingToAnyRefusedAddress(array $addresses): void
    {
        $result = $this->fetcher([], [self::HOST => $addresses])->fetch(FetchRequest::metadata(self::URL));

        self::assertSame(FetchStatus::REFUSED, $result->status);
        self::assertSame([], $this->sent);
        self::assertSame([self::HOST], $this->resolver->lookups());
        self::assertSame('refused_address', $this->loggedContext()['cause']);
    }

    /**
     * A host that resolves to nothing fails, once resolved, with nothing sent.
     *
     * @return void
     */
    public function testAnUnresolvableHostFails(): void
    {
        $result = $this->fetcher([], [])->fetch(FetchRequest::metadata(self::URL));

        self::assertSame(FetchStatus::FAILED, $result->status);
        self::assertSame(FailureReason::FETCH_FAILED, $result->reason);
        self::assertSame([], $this->sent);
        self::assertSame([self::HOST], $this->resolver->lookups());
        self::assertSame('unresolved', $this->loggedContext()['cause']);
    }

    /**
     * Rows of `[url, addresses, pin]`: what each host and port is pinned to.
     *
     * @return iterable<string, array{0: string, 1: list<string>, 2: string}>
     */
    public static function providePins(): iterable
    {
        yield from [
            'the default port'     => [self::URL, [self::ADDRESS], 'idp.example.com:443:93.184.216.34'],
            'the first of several' => [self::URL, [self::ADDRESS, '93.184.216.35'], 'idp.example.com:443:93.184.216.34'],
            'an explicit port'     => ['https://idp.example.com:8443/metadata', [self::ADDRESS], 'idp.example.com:8443:93.184.216.34'],
            'an explicit 443'      => ['https://idp.example.com:443/metadata', [self::ADDRESS], 'idp.example.com:443:93.184.216.34'],
            'ipv6, bracketed'      => [self::URL, ['2606:4700:4700::1111'], 'idp.example.com:443:[2606:4700:4700::1111]'],
            'ipv6, made canonical' => [self::URL, ['2606:4700:4700:0:0:0:0:1111'], 'idp.example.com:443:[2606:4700:4700::1111]'],
            'ipv6 and a port'      => ['https://idp.example.com:8443/', ['2606:4700:4700::1111'], 'idp.example.com:8443:[2606:4700:4700::1111]'],
        ];
    }

    /**
     * The connection is pinned with `CURLOPT_RESOLVE` to the first checked
     * address, as `host:port:address` with an IPv6 address in brackets, and the
     * request keeps the host name, so the certificate is verified against it.
     *
     * @param  string  $url
     * @param  list<string>  $addresses
     * @param  string  $pin
     * @return void
     */
    #[DataProvider('providePins')]
    public function testPinsTheCheckedAddress(string $url, array $addresses, string $pin): void
    {
        $result = $this->fetcher([new Response(200, [], 'ok')], [self::HOST => $addresses])->fetch(FetchRequest::metadata($url));

        self::assertTrue($result->isFetched());
        self::assertSame([$pin], $this->curlOptions()[CURLOPT_RESOLVE]);
        self::assertSame(self::HOST, $this->sentRequest()->getUri()->getHost());
    }

    /**
     * A canonical public IP literal is sent without a lookup or a pin: there is
     * no name to resolve a second time.
     *
     * @return void
     */
    public function testSendsToAPublicLiteralWithoutResolving(): void
    {
        $fetcher = $this->fetcher([new Response(200, [], 'ok'), new Response(200, [], 'ok')]);

        self::assertTrue($fetcher->fetch(FetchRequest::metadata('https://93.184.216.34/metadata'))->isFetched());
        self::assertTrue($fetcher->fetch(FetchRequest::metadata('https://[2606:4700:4700::1111]/metadata'))->isFetched());

        self::assertSame([], $this->resolver->lookups());
        self::assertSame('https://93.184.216.34/metadata', (string) $this->sentRequest(0)->getUri());
        self::assertSame('https://[2606:4700:4700::1111]/metadata', (string) $this->sentRequest(1)->getUri());
        self::assertArrayNotHasKey(CURLOPT_RESOLVE, $this->curlOptions(0));
        self::assertArrayNotHasKey(CURLOPT_RESOLVE, $this->curlOptions(1));
    }

    /**
     * Every request is sent with redirects, HTTP errors, cookies, proxies and
     * content decoding off, certificate verification on, `https` the only
     * protocol and the configured time caps; on a Guzzle that leaves them to
     * the caller, the matching cURL options are set too.
     *
     * @return void
     */
    public function testSendsWithTheFixedTransportOptions(): void
    {
        config()->set('sso.fetcher.timeout_seconds', 20);
        config()->set('sso.fetcher.connect_timeout_seconds', 7);

        $this->fetcher([new Response(200, [], 'ok')])->fetch(FetchRequest::metadata(self::URL));

        $options = $this->sentOptions();

        self::assertFalse($options['allow_redirects']);
        self::assertFalse($options['http_errors']);
        self::assertTrue($options['verify']);
        self::assertFalse($options['cookies']);
        self::assertSame('', $options['proxy']);
        self::assertFalse($options['decode_content']);
        self::assertSame(['https'], $options['protocols']);
        self::assertSame(20.0, $options['timeout']);
        self::assertSame(7.0, $options['connect_timeout']);

        $managed = [
            CURLOPT_PROTOCOLS       => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION  => false,
            CURLOPT_NOPROXY         => '*',
        ];

        $curl = $this->curlOptions();

        unset($curl[CURLOPT_RESOLVE]);

        self::assertSame(self::isCurlOptionSetByGuzzle() ? [] : $managed, $curl);
    }

    /**
     * Rows of `[request, accept]`: a request of each purpose and the `Accept`
     * header it carries.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchRequest, 1: string}>
     */
    public static function providePurposes(): iterable
    {
        yield from [
            'metadata'  => [FetchRequest::metadata(self::URL), 'application/samlmetadata+xml, application/xml;q=0.9, text/xml;q=0.8'],
            'discovery' => [FetchRequest::discovery(self::URL), 'application/json'],
            'jwks'      => [FetchRequest::jwks(self::URL), 'application/jwk-set+json, application/json;q=0.9'],
            'token'     => [FetchRequest::token(self::URL, ['grant_type' => 'authorization_code'], FetchCredentials::clientSecretBasic('client', 'secret')), 'application/json'],
            'userinfo'  => [FetchRequest::userInfo(self::URL, FetchCredentials::accessToken('token')), 'application/json'],
        ];
    }

    /**
     * Each purpose asks for its own media types, as `laravel-sso`, and never
     * for an encoded body.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @param  string  $accept
     * @return void
     */
    #[DataProvider('providePurposes')]
    public function testAcceptsPerPurposeWithoutEncoding(FetchRequest $request, string $accept): void
    {
        $this->fetcher([new Response(200, [], 'ok')])->fetch($request);

        $sent = $this->sentRequest();

        self::assertSame($accept, $sent->getHeaderLine('Accept'));
        self::assertSame('laravel-sso', $sent->getHeaderLine('User-Agent'));
        self::assertFalse($sent->hasHeader('Accept-Encoding'));
        self::assertFalse($sent->hasHeader('Cookie'));
    }

    /**
     * A declared length over the cap fails, through the headers callback that
     * aborts the transfer before the body.
     *
     * @return void
     */
    public function testADeclaredLengthOverTheCapFails(): void
    {
        config()->set('sso.fetcher.max_response_bytes', 1024);

        $result = $this->fetcher([new Response(200, ['Content-Length' => '1025'], 'small')])->fetch(FetchRequest::metadata(self::URL));

        self::assertSame(FetchStatus::FAILED, $result->status);
        self::assertSame('too_large', $this->loggedContext()['cause']);
    }

    /**
     * A body over the cap fails, a body of exactly the cap is fetched.
     *
     * @return void
     */
    public function testABodyOverTheCapFails(): void
    {
        config()->set('sso.fetcher.max_response_bytes', 1024);

        $fetcher = $this->fetcher([new Response(200, [], str_repeat('a', 1025)), new Response(200, [], str_repeat('a', 1024))]);

        $over = $fetcher->fetch(FetchRequest::metadata(self::URL));

        self::assertSame(FetchStatus::FAILED, $over->status);
        self::assertSame('too_large', $this->loggedContext()['cause']);

        $at = $fetcher->fetch(FetchRequest::metadata(self::URL));

        self::assertTrue($at->isFetched());
        self::assertSame(1024, strlen((string) $at->body()));
    }

    /**
     * The headers callback refuses a declared length over the cap and lets one
     * at the cap, or none, through; the progress callback asks the transfer to
     * stop once the bytes received pass the cap, which Guzzle 8 acts on (the
     * sink stops it on every Guzzle).
     *
     * @return void
     */
    public function testTheCapCallbacksStopTheTransfer(): void
    {
        config()->set('sso.fetcher.max_response_bytes', 1024);

        $this->fetcher([new Response(200, [], 'ok')])->fetch(FetchRequest::metadata(self::URL));

        $options   = $this->sentOptions();
        $onHeaders = $options['on_headers'];
        $progress  = $options['progress'];

        self::assertIsCallable($onHeaders);
        self::assertIsCallable($progress);

        $onHeaders(new Response(200, ['Content-Length' => '1024']));
        $onHeaders(new Response(200));
        $onHeaders(new Response(200, ['Content-Length' => 'not a number']));

        self::assertFalse($progress(0, 0, 0, 0));
        self::assertFalse($progress(2048, 1024, 0, 0));
        self::assertTrue($progress(2048, 1025, 0, 0));

        $this->expectException(\OverflowException::class);

        $onHeaders(new Response(200, ['Content-Length' => '99999999999999999999999']));
    }

    /**
     * The body is written into a sink that takes bytes up to the cap and
     * refuses the write that would pass it, answering `0`, which makes cURL
     * abort the transfer with a write error on every supported Guzzle.
     *
     * @return void
     */
    public function testTheSinkRefusesTheWritePastTheCap(): void
    {
        config()->set('sso.fetcher.max_response_bytes', 1024);

        $this->fetcher([new Response(200, [], 'ok')])->fetch(FetchRequest::metadata(self::URL));

        $sink = $this->sentOptions()['sink'] ?? null;

        self::assertInstanceOf(StreamInterface::class, $sink);
        self::assertSame(1022, $sink->write(str_repeat('a', 1022)));
        self::assertSame(0, $sink->write('a'));
        self::assertSame(0, $sink->write(''));
        self::assertSame(1024, $sink->getSize());
    }

    /**
     * A body sent without a declared length is cut off at the cap, whatever the
     * Guzzle version makes of the progress callback: a handler that writes it
     * into the sink as cURL does, chunk by chunk, aborting on the first short
     * write, is stopped at the first chunk past the cap; the hop fails as too
     * large, and no more than the cap is ever held.
     *
     * @return void
     */
    public function testABodyWithoutALengthIsCutOffAtTheCap(): void
    {
        config()->set('sso.fetcher.max_response_bytes', 1024);

        /** @var \ArrayObject<int, int> $offered */
        $offered = new \ArrayObject;
        $handler = static function (RequestInterface $request, array $options) use ($offered): PromiseInterface {
            $sink = $options['sink'];

            self::assertInstanceOf(StreamInterface::class, $sink);

            for ($chunk = 0; $chunk < 1000; $chunk++) {
                $offered->append(512);

                if ($sink->write(str_repeat('a', 512)) !== 512) {
                    return Create::rejectionFor(new RequestException('cURL error 23: Failure writing output to destination', $request));
                }
            }

            return Create::promiseFor(new Response(200, [], $sink));
        };

        $settings = new FetcherSettings(config());
        $log      = new TestHandler;
        $fetcher  = new GuzzleFetcher($settings, new AddressPolicy($settings), new Logger('sso', [$log]), new StubHostResolver([self::HOST => [self::ADDRESS]]), $handler);
        $result   = $fetcher->fetch(FetchRequest::metadata(self::URL));

        self::assertSame(FetchStatus::FAILED, $result->status);
        self::assertSame('too_large', $log->getRecords()[0]->context['cause'] ?? null);
        self::assertSame(1536, array_sum($offered->getArrayCopy()));
    }

    /**
     * A request Guzzle or PSR-7 refuses to build (a header value it rejects,
     * say) fails like a transport error rather than escaping as an exception,
     * logged with the exception's class and never its message, which can quote
     * the value.
     *
     * @return void
     */
    public function testARequestThatCannotBeBuiltFails(): void
    {
        $thrown = new \InvalidArgumentException('"Bearer the-access-token" is not valid header value.');
        $result = $this->fetcher([$thrown])->fetch(FetchRequest::userInfo(self::URL, FetchCredentials::accessToken('the-access-token')));

        self::assertSame(FetchStatus::FAILED, $result->status);
        self::assertSame(FailureReason::FETCH_FAILED, $result->reason);
        self::assertSame('transfer', $this->loggedContext()['cause']);
        self::assertSame(\InvalidArgumentException::class, $this->loggedContext()['exception_class']);
        self::assertStringNotContainsString('the-access-token', $this->logged());
    }

    /**
     * Rows of `[exception]`: transport failures, a TLS failure among them.
     *
     * @return iterable<string, array{0: \Closure(): \Throwable}>
     */
    public static function provideTransportFailures(): iterable
    {
        $request = new Request('GET', self::URL);

        yield from [
            'a refused connection' => [static fn (): \Throwable => new ConnectException('cURL error 7: Failed to connect to idp.example.com', $request)],
            'a timeout'            => [static fn (): \Throwable => new ConnectException('cURL error 28: Operation timed out', $request)],
            'a bad certificate'    => [static fn (): \Throwable => new RequestException('cURL error 60: SSL certificate problem', $request)],
            'a host name mismatch' => [static fn (): \Throwable => new RequestException('cURL error 51: SSL: no alternative certificate subject name matches', $request)],
        ];
    }

    /**
     * A transport or TLS failure fails the fetch, logged with the exception's
     * class and never its message.
     *
     * @param  \Closure(): \Throwable  $exception
     * @return void
     */
    #[DataProvider('provideTransportFailures')]
    public function testATransportFailureFails(\Closure $exception): void
    {
        $thrown = $exception();
        $result = $this->fetcher([$thrown])->fetch(FetchRequest::metadata(self::URL));

        self::assertSame(FetchStatus::FAILED, $result->status);
        self::assertSame(FailureReason::FETCH_FAILED, $result->reason);
        self::assertSame('transfer', $this->loggedContext()['cause']);
        self::assertSame($thrown::class, $this->loggedContext()['exception_class']);
        self::assertStringNotContainsString('cURL error', $this->logged());
    }

    /**
     * A response of any HTTP status is fetched: whether a `400` is an error is
     * the caller's to read; each header is answered with its first value.
     *
     * @return void
     */
    public function testAnErrorStatusIsFetched(): void
    {
        $response = new Response(400, ['Content-Type' => 'application/json', 'X-Repeated' => ['first', 'second']], '{"error":"invalid_grant"}');
        $result   = $this->fetcher([$response])->fetch(FetchRequest::discovery(self::URL));

        self::assertTrue($result->isFetched());
        self::assertFalse($result->isSuccessful());
        self::assertSame(400, $result->statusCode);
        self::assertNull($result->reason);
        self::assertSame('{"error":"invalid_grant"}', $result->body());
        self::assertSame('application/json', $result->header('content-type'));
        self::assertSame('first', $result->header('X-Repeated'));
        self::assertSame([], $this->log->getRecords());
    }

    /**
     * A refusal and a failure carry their reason code only: no status, header
     * or body, and nothing of the URL.
     *
     * @return void
     */
    public function testARefusalOrFailureCarriesOnlyItsReasonCode(): void
    {
        $fetcher = $this->fetcher([new ConnectException('down', new Request('GET', self::URL))]);

        $refused = $fetcher->fetch(FetchRequest::metadata('http://idp.example.com/secret-path?q=1'));
        $failed  = $fetcher->fetch(FetchRequest::metadata(self::URL));

        foreach ([[$refused, FetchStatus::REFUSED, FailureReason::FETCH_REFUSED], [$failed, FetchStatus::FAILED, FailureReason::FETCH_FAILED]] as [$result, $status, $reason]) {
            self::assertSame($status, $result->status);
            self::assertSame($reason, $result->reason);
            self::assertNull($result->statusCode);
            self::assertNull($result->body());
            self::assertNull($result->header('content-type'));
            self::assertSame(['status' => $status->value, 'statusCode' => null, 'headers' => [], 'body' => null, 'reason' => $reason->value], $result->__debugInfo());
        }
    }

    /**
     * Each refusal and failure is logged once, as a warning with the allowed
     * context only: never the URL's path or query, the form, a credential, the
     * exception's message or the body.
     *
     * @return void
     */
    public function testLogsOneWarningWithoutTheRequestOrResponse(): void
    {
        $credentials = FetchCredentials::clientSecretPost('client-1', 'the-client-secret');
        $form        = ['grant_type' => 'authorization_code', 'code' => 'the-auth-code', 'code_verifier' => 'the-verifier'];
        $request     = FetchRequest::token('https://idp.example.com/oauth/token?tenant=secret-query', $form, $credentials);
        $exception   = new ConnectException('cURL error 7: idp.example.com/oauth/token?tenant=secret-query the-client-secret', new Request('POST', $request->url));

        $this->fetcher([$exception])->fetch($request);

        $records = $this->log->getRecords();

        self::assertCount(1, $records);
        self::assertSame(Level::Warning, $records[0]->level);
        self::assertSame('sso.fetch.failed', $records[0]->message);
        self::assertSame([
            'purpose'         => 'token',
            'reason'          => 'fetch_failed',
            'cause'           => 'transfer',
            'host'            => self::HOST,
            'exception_class' => ConnectException::class,
        ], $records[0]->context);

        foreach (['oauth', 'secret-query', 'the-auth-code', 'the-verifier', 'the-client-secret', 'client-1', 'cURL error'] as $secret) {
            self::assertStringNotContainsString($secret, $this->logged());
        }
    }

    /**
     * A refusal is logged under its own message, with the same allowed keys and
     * no exception class.
     *
     * @return void
     */
    public function testLogsARefusal(): void
    {
        $this->fetcher()->fetch(FetchRequest::jwks('http://idp.example.com/keys?kid=secret-kid'));

        $records = $this->log->getRecords();

        self::assertCount(1, $records);
        self::assertSame(Level::Warning, $records[0]->level);
        self::assertSame('sso.fetch.refused', $records[0]->message);
        self::assertSame(['purpose' => 'jwks', 'reason' => 'fetch_refused', 'cause' => 'scheme', 'host' => self::HOST], $records[0]->context);
        self::assertStringNotContainsString('secret-kid', $this->logged());
    }

    /**
     * A body over the cap is not logged, and a successful fetch logs nothing.
     *
     * @return void
     */
    public function testNeverLogsTheBody(): void
    {
        config()->set('sso.fetcher.max_response_bytes', 1024);

        $fetcher = $this->fetcher([new Response(200, [], 'secret-body' . str_repeat('a', 1024)), new Response(200, [], 'secret-body')]);

        $fetcher->fetch(FetchRequest::metadata(self::URL));

        self::assertCount(1, $this->log->getRecords());
        self::assertSame([], array_diff(array_keys($this->loggedContext()), self::LOGGED_KEYS));
        self::assertStringNotContainsString('secret-body', $this->logged());

        $fetcher->fetch(FetchRequest::metadata(self::URL));

        self::assertCount(1, $this->log->getRecords());
    }

    /**
     * An internationalised host is converted to ASCII before it is resolved,
     * pinned and sent.
     *
     * @return void
     */
    public function testNormalizesAnInternationalizedHostToAscii(): void
    {
        $result = $this->fetcher([new Response(200, [], 'ok')], ['xn--bcher-kva.example' => [self::ADDRESS]])->fetch(FetchRequest::metadata('https://BÜCHER.example/metadata'));

        self::assertTrue($result->isFetched());
        self::assertSame(['xn--bcher-kva.example'], $this->resolver->lookups());
        self::assertSame('xn--bcher-kva.example', $this->sentRequest()->getUri()->getHost());
        self::assertSame(['xn--bcher-kva.example:443:93.184.216.34'], $this->curlOptions()[CURLOPT_RESOLVE]);
    }

    /**
     * One trailing dot is stripped from the host before it is resolved, pinned
     * and sent.
     *
     * @return void
     */
    public function testStripsATrailingDot(): void
    {
        $result = $this->fetcher([new Response(200, [], 'ok')])->fetch(FetchRequest::metadata('https://idp.example.com./metadata'));

        self::assertTrue($result->isFetched());
        self::assertSame([self::HOST], $this->resolver->lookups());
        self::assertSame(self::URL, (string) $this->sentRequest()->getUri());
        self::assertSame(['idp.example.com:443:93.184.216.34'], $this->curlOptions()[CURLOPT_RESOLVE]);
    }

    /**
     * The path and query are sent as given.
     *
     * @return void
     */
    public function testSendsThePathAndQuery(): void
    {
        $this->fetcher([new Response(200, [], 'ok')])->fetch(FetchRequest::discovery('https://idp.example.com/tenant/a/.well-known/openid-configuration?x=1&y=two'));

        self::assertSame('https://idp.example.com/tenant/a/.well-known/openid-configuration?x=1&y=two', (string) $this->sentRequest()->getUri());
        self::assertSame('GET', $this->sentRequest()->getMethod());
    }

    /**
     * An internationalised host with a port keeps the port, and a path or query
     * beyond ASCII is sent percent-encoded rather than rewritten.
     *
     * @return void
     */
    public function testSendsAnInternationalizedUrlInAscii(): void
    {
        $fetcher = $this->fetcher([new Response(200, [], 'ok')], ['xn--bcher-kva.example' => [self::ADDRESS]]);
        $result  = $fetcher->fetch(FetchRequest::metadata('https://bücher.example:8443/métadonnées?q=ü'));

        self::assertTrue($result->isFetched());
        self::assertSame('https://xn--bcher-kva.example:8443/m%C3%A9tadonn%C3%A9es?q=%C3%BC', (string) $this->sentRequest()->getUri());
        self::assertSame(['xn--bcher-kva.example:8443:93.184.216.34'], $this->curlOptions()[CURLOPT_RESOLVE]);
    }

    /**
     * An injected handler is used even where `ext-curl` would be missing: only
     * the default cURL handler needs it.
     *
     * @return void
     */
    public function testAnInjectedHandlerNeedsNoCurl(): void
    {
        $settings = new FetcherSettings(config());

        $fetcher = new GuzzleFetcher($settings, new AddressPolicy($settings), new Logger('sso'), new StubHostResolver, new MockHandler, static fn (): bool => false);

        self::assertInstanceOf(GuzzleFetcher::class, $fetcher);
    }

    /**
     * Build a fetcher over a mock handler answering with the responses in turn,
     * a stub resolver of the hosts given, a capturing logger and a monotonic
     * clock that stands still, so each request is given the whole timeout.
     *
     * @param  list<\Psr\Http\Message\ResponseInterface|\Throwable>  $responses
     * @param  array<string, list<string>>  $hosts
     * @return \SineMacula\Laravel\Sso\Fetching\GuzzleFetcher
     */
    private function fetcher(array $responses = [], array $hosts = [self::HOST => [self::ADDRESS]]): GuzzleFetcher
    {
        $mock = new MockHandler($responses);

        $this->sent     = [];
        $this->log      = new TestHandler;
        $this->resolver = new StubHostResolver($hosts);

        $handler = function (RequestInterface $request, array $options) use ($mock): PromiseInterface {
            $this->sent[] = ['request' => $request, 'options' => $options];

            return $mock($request, $options);
        };

        $settings = new FetcherSettings(config());

        return new GuzzleFetcher($settings, new AddressPolicy($settings), new Logger('sso', [$this->log]), $this->resolver, $handler, null, static fn (): int => 0);
    }

    /**
     * Assert the result is a refusal and nothing was resolved or sent.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $result
     * @return void
     */
    private function assertRefusedBeforeSending(FetchResult $result): void
    {
        self::assertSame(FetchStatus::REFUSED, $result->status);
        self::assertSame(FailureReason::FETCH_REFUSED, $result->reason);
        self::assertSame([], $this->sent);
        self::assertSame([], $this->resolver->lookups());
        self::assertCount(1, $this->log->getRecords());
    }

    /**
     * The request the mock handler received at the index.
     *
     * @param  int  $index
     * @return \Psr\Http\Message\RequestInterface
     */
    private function sentRequest(int $index = 0): RequestInterface
    {
        self::assertArrayHasKey($index, $this->sent);

        return $this->sent[$index]['request'];
    }

    /**
     * The options the mock handler received at the index.
     *
     * @param  int  $index
     * @return array<string, mixed>
     */
    private function sentOptions(int $index = 0): array
    {
        self::assertArrayHasKey($index, $this->sent);

        return $this->sent[$index]['options'];
    }

    /**
     * The cURL options the mock handler received at the index.
     *
     * @param  int  $index
     * @return array<int, mixed>
     */
    private function curlOptions(int $index = 0): array
    {
        $curl = $this->sentOptions($index)['curl'] ?? null;

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

    /**
     * Everything logged, as one string.
     *
     * @return string
     */
    private function logged(): string
    {
        return json_encode(array_map(static fn (LogRecord $record): array => [$record->message, $record->context], $this->log->getRecords()), JSON_THROW_ON_ERROR);
    }

    /**
     * Whether the installed Guzzle sets the protocol, redirect and proxy cURL
     * options itself (Guzzle 8 and later), so the fetcher leaves them out.
     *
     * @return bool
     */
    private static function isCurlOptionSetByGuzzle(): bool
    {
        $version = (new \ReflectionClassConstant(ClientInterface::class, 'MAJOR_VERSION'))->getValue();

        return is_int($version) && $version >= 8;
    }
}
