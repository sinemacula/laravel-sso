<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OutboundRequests;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use Illuminate\Process\PendingProcess;
use Illuminate\Support\Facades\Process;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\HostResolver;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\AddressPolicy;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetcherSettings;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use SineMacula\Laravel\Sso\Metadata\DiscoveryImporter;
use SineMacula\Laravel\Sso\Metadata\MetadataImporter;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process as SymfonyProcess;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/outbound-requests.md` (SSO-2.9, SSO-12.5), on
 * the shared example harness: the application's own refused ranges published in
 * `config/sso.php`, its own fetcher bound for an egress proxy, its own bounded
 * host resolver bound for a slow system resolver, and the fake fetcher
 * answering the requests of the code under test. Each asserts its outcome and a
 * refusal: an address in a published range refused, a range that is not one
 * failing closed, a URL the proxied fetcher may not send, a lookup that runs
 * out failing the fetch unsent, and a URL the fake answers with a failure.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AddressPolicy::class)]
#[CoversClass(FetcherSettings::class)]
#[CoversClass(GuzzleFetcher::class)]
#[CoversClass(FakeFetcher::class)]
final class OutboundRequestsExampleTest extends ExampleTestCase
{
    /** @var string The egress proxy the application's network requires. */
    private const string PROXY = 'http://proxy.internal:3128';

    /** @var string A host of a partner's, which resolves into the partner's refused network. */
    private const string PARTNER_HOST = 'idp.partner.example';

    /**
     * The published ranges are refused on top of the ones always refused, IPv6
     * forms that carry an IPv4 address included, and none of their neighbours
     * is; before the configuration is published, none of them is.
     *
     * @return void
     */
    public function testThePublishedRangesAreRefusedOnTopOfTheBuiltInOnes(): void
    {
        $policy = app(AddressPolicy::class);

        self::assertFalse($policy->isRefused('203.0.114.5'));
        self::assertTrue($policy->isRefused('203.0.113.5'));

        $this->publishConfiguration();

        $refused = ['203.0.114.0', '203.0.114.5', '203.0.114.255', '198.51.101.7', '3fff:42::1', '3fff:42:ffff::1', '::ffff:203.0.114.5', '64:ff9b::203.0.114.5'];
        $allowed = ['203.0.115.5', '203.0.112.255', '198.51.101.6', '198.51.101.8', '3fff:43::1', '93.184.215.14'];

        self::assertSame(array_fill_keys($refused, true), array_combine($refused, array_map($policy->isRefused(...), $refused)));
        self::assertSame(array_fill_keys($allowed, false), array_combine($allowed, array_map($policy->isRefused(...), $allowed)));
        self::assertTrue($policy->isRefused('169.254.169.254'));
        self::assertTrue($policy->isRefused('2001:db8::1'));
    }

    /**
     * The default fetcher refuses a host that resolves into a published range
     * as `fetch_refused`, having sent nothing.
     *
     * @return void
     */
    public function testTheDefaultFetcherRefusesAHostThatResolvesIntoAPublishedRange(): void
    {
        $this->publishConfiguration();

        app()->register(BoundedDnsServiceProvider::class);

        Process::fake(static fn (PendingProcess $process): string => self::recordType($process) === 'A' ? "203.0.114.20\n" : '');

        $result = app(GuzzleFetcher::class)->fetch(FetchRequest::metadata('https://' . self::PARTNER_HOST . '/metadata'));

        self::assertSame(FetchStatus::REFUSED, $result->status);
        self::assertSame(FailureReason::FETCH_REFUSED, $result->reason);
        self::assertNull($result->statusCode);
    }

    /**
     * A refused range that is not a CIDR range fails closed when it is read,
     * naming its key, rather than refusing less.
     *
     * @return void
     */
    public function testARangeThatIsNotACidrRangeFailsClosedNamingItsKey(): void
    {
        config()->set('sso.fetcher.refused_ranges', ['203.0.114.0/24', '198.51.101.7/32', '3fff:42::/129']);

        $this->expectExceptionObject(new \InvalidArgumentException(
            'sso.fetcher.refused_ranges.2 must be a CIDR range: an IPv4 address with /0 to /32, or an IPv6 address with /0 to /128.',
        ));

        app(AddressPolicy::class)->isRefused('93.184.215.14');
    }

    /**
     * The application's provider binds its fetcher in place of the package's,
     * one for each request or job: the same within a scope, and a new one once
     * the scope ends.
     *
     * @return void
     */
    public function testTheProxiedFetcherIsBoundOncePerRequestOrJob(): void
    {
        config()->set('services.egress.proxy', self::PROXY);

        app()->register(EgressProxyServiceProvider::class);

        $first = app(Fetcher::class);

        self::assertInstanceOf(ProxiedFetcher::class, $first);
        self::assertSame($first, app(Fetcher::class));

        app()->forgetScopedInstances();

        self::assertInstanceOf(ProxiedFetcher::class, app(Fetcher::class));
        self::assertNotSame($first, app(Fetcher::class));
    }

    /**
     * A token request leaves through the proxy, its certificate verified and no
     * redirect followed, with its form and its one credential in the
     * `Authorization: Basic` header, each part form-encoded first.
     *
     * @return void
     */
    public function testTheProxiedFetcherSendsTheOneCredentialThroughTheProxy(): void
    {
        $handler = new MockHandler([new Response(200, ['Content-Type' => 'application/json'], '{"access_token":"at-1"}')]);
        $form    = ['grant_type' => 'authorization_code', 'code' => 'code-1'];
        $result  = $this->proxiedFetcher($handler)->fetch(FetchRequest::token('https://idp.example.com/token', $form, FetchCredentials::clientSecretBasic('client 1', 's3cr:t')));
        $sent    = $handler->getLastRequest();
        $options = $handler->getLastOptions();

        self::assertTrue($result->isSuccessful());
        self::assertSame('{"access_token":"at-1"}', $result->body());
        self::assertSame('application/json', $result->header('content-type'));

        self::assertNotNull($sent);
        self::assertSame('POST', $sent->getMethod());
        self::assertSame('https://idp.example.com/token', (string) $sent->getUri());
        self::assertSame('Basic ' . base64_encode('client+1:s3cr%3At'), $sent->getHeaderLine('Authorization'));
        self::assertSame('grant_type=authorization_code&code=code-1', (string) $sent->getBody());
        self::assertFalse($sent->hasHeader('Cookie'));

        self::assertSame(['https' => self::PROXY], $options['proxy'] ?? null);
        self::assertTrue($options['verify'] ?? null);
        self::assertFalse($options['allow_redirects'] ?? null);
        self::assertFalse($options['decode_content'] ?? null);
    }

    /**
     * Rows of `[a URL the default fetcher refuses before sending]`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUrlsRefused(): iterable
    {
        yield 'plain http' => ['http://idp.example.com/jwks'];
        yield 'user information' => ['https://admin@idp.example.com/jwks'];
        yield 'fragment' => ['https://idp.example.com/jwks#keys'];
        yield 'shortened IPv4' => ['https://127.1/jwks'];
        yield 'hexadecimal IPv4' => ['https://0x7f.1/jwks'];
        yield 'decimal IPv4' => ['https://2130706433/jwks'];
        yield 'IPv6 loopback' => ['https://[::1]/jwks'];
        yield 'cloud metadata' => ['https://169.254.169.254/latest/meta-data'];
        yield 'published range' => ['https://203.0.114.9/jwks'];
    }

    /**
     * The proxied fetcher refuses, unsent, what the default fetcher refuses,
     * the published ranges included.
     *
     * @param  string  $url
     * @return void
     */
    #[DataProvider('provideUrlsRefused')]
    public function testTheProxiedFetcherRefusesWhatTheDefaultFetcherWould(string $url): void
    {
        $this->publishConfiguration();

        $handler = new MockHandler([new Response(200, [], '{"keys":[]}')]);
        $result  = $this->proxiedFetcher($handler)->fetch(FetchRequest::jwks($url));

        self::assertSame(FetchStatus::REFUSED, $result->status);
        self::assertSame(FailureReason::FETCH_REFUSED, $result->reason);
        self::assertCount(1, $handler);
    }

    /**
     * A redirect comes back as the response it is, never followed, and a body
     * past the request's own cap fails the fetch, while one at the cap is
     * fetched.
     *
     * @return void
     */
    public function testTheProxiedFetcherFollowsNoRedirectAndHoldsTheSizeCap(): void
    {
        $handler = new MockHandler([
            new Response(302, ['Location' => 'https://elsewhere.example.com/jwks']),
            new Response(200, [], str_repeat('x', 1024)),
            new Response(200, [], str_repeat('x', 1025)),
        ]);
        $fetcher = $this->proxiedFetcher($handler);

        $redirected = $fetcher->fetch(FetchRequest::jwks('https://idp.example.com/jwks'));

        self::assertSame(302, $redirected->statusCode);
        self::assertFalse($redirected->isSuccessful());
        self::assertSame('https://elsewhere.example.com/jwks', $redirected->header('location'));
        self::assertCount(2, $handler);

        self::assertSame(1024, strlen((string) $fetcher->fetch(FetchRequest::metadata('https://idp.example.com/metadata', 1024))->body()));

        $capped = $fetcher->fetch(FetchRequest::metadata('https://idp.example.com/metadata', 1024));

        self::assertSame(FetchStatus::FAILED, $capped->status);
        self::assertSame(FailureReason::FETCH_FAILED, $capped->reason);
    }

    /**
     * The proxied fetcher refuses to be built with no proxy to send through,
     * rather than send directly.
     *
     * @return void
     */
    public function testTheProxiedFetcherNeedsItsProxy(): void
    {
        app()->register(EgressProxyServiceProvider::class);

        $this->expectExceptionObject(new \LogicException('services.egress.proxy must name the egress proxy.'));

        app(Fetcher::class);
    }

    /**
     * The application's provider binds its resolver in place of the package's,
     * one for every request and job, which asks `dig` for the A and then the
     * AAAA records, each lookup bounded, and answers only their IP literals.
     *
     * @return void
     */
    public function testTheBoundedResolverIsBoundOnceAndAnswersOnlyAddresses(): void
    {
        app()->register(BoundedDnsServiceProvider::class);

        $ran = [];

        Process::fake(static function (PendingProcess $process) use (&$ran): string {

            $ran[] = [$process->command, $process->timeout];

            return self::recordType($process) === 'A' ? "idp.cdn.example.net.\n93.184.215.14\n" : "idp.cdn.example.net.\n2606:2800:21f:cb07:6820:80da:af6b:8b2c\n";
        });

        $resolver = app(HostResolver::class);

        self::assertInstanceOf(BoundedHostResolver::class, $resolver);
        self::assertSame($resolver, app(HostResolver::class));
        self::assertSame(['93.184.215.14', '2606:2800:21f:cb07:6820:80da:af6b:8b2c'], $resolver->addresses('idp.example.com'));
        self::assertSame([
            [['dig', '+short', '+time=2', '+tries=1', 'A', 'idp.example.com.'], 3],
            [['dig', '+short', '+time=2', '+tries=1', 'AAAA', 'idp.example.com.'], 3],
        ], $ran);
    }

    /**
     * A lookup that overruns its process's timeout, and one `dig` gives up on
     * itself, add no address, so the name answers `[]` and the default fetcher
     * fails the fetch as `fetch_failed` without sending it.
     *
     * @return void
     */
    public function testALookupThatRunsOutAnswersNothingAndTheFetchFailsUnsent(): void
    {
        app()->register(BoundedDnsServiceProvider::class);

        Process::fake(static function (PendingProcess $process): mixed {

            if (self::recordType($process) === 'A') {
                throw new ProcessTimedOutException(new SymfonyProcess((array) $process->command), ProcessTimedOutException::TYPE_GENERAL);
            }

            return Process::result(';; connection timed out; no servers could be reached', exitCode: 9);
        });

        self::assertSame([], app(HostResolver::class)->addresses('idp.example.com'));

        $result = app(GuzzleFetcher::class)->fetch(FetchRequest::jwks('https://idp.example.com/jwks'));

        self::assertSame(FetchStatus::FAILED, $result->status);
        self::assertSame(FailureReason::FETCH_FAILED, $result->reason);
    }

    /**
     * The fake fetcher answers the code under test, a SAML metadata import and
     * an OpenID discovery import: the JWKS it fails refuses the discovery
     * import with `fetch_failed`, and the one a closure builds from the keys
     * the provider publishes lets it propose; each URL is fetched for its
     * purpose.
     *
     * @return void
     */
    public function testTheFakeFetcherAnswersTheCodeUnderTest(): void
    {
        // @snippet-start outbound-fake-fetcher
        $idp      = new FakeSamlIdentityProvider;
        $provider = new FakeOpenIdProvider('https://op.example.com');

        $fetcher = (new FakeFetcher)
            ->respond('https://idp.example.com/metadata', FetchResult::fetched(200, ['Content-Type' => 'application/xml'], $idp->metadata()->toXml()))
            ->respond('https://op.example.com/.well-known/openid-configuration', FetchResult::fetched(200, [], (string) json_encode($provider->discovery())))
            ->respond('https://op.example.com/jwks', FetchResult::failed());

        $this->instance(Fetcher::class, $fetcher);

        // The code under test: import each provider's metadata
        $saml = app(MetadataImporter::class)->importUrl('tenant-1', null, 'https://idp.example.com/metadata', $idp->entityId);
        $oidc = app(DiscoveryImporter::class)->import('tenant-1', 'https://op.example.com');

        self::assertTrue($saml->isProposed());
        self::assertSame(FailureReason::FETCH_FAILED, $oidc->reason);

        // A closure builds the response when the request is made
        $fetcher->respond('https://op.example.com/jwks', static fn (): FetchResult => FetchResult::fetched(200, [], (string) json_encode($provider->jwks())));

        self::assertTrue(app(DiscoveryImporter::class)->import('tenant-1', 'https://op.example.com')->isProposed());

        $fetcher->assertFetched('https://idp.example.com/metadata', FetchPurpose::METADATA);
        $fetcher->assertFetched('https://op.example.com/jwks', FetchPurpose::JWKS);
        // @snippet-end outbound-fake-fetcher
        self::assertSame(
            ['metadata', 'discovery', 'jwks', 'discovery', 'jwks'],
            array_map(static fn (FetchRequest $request): string => $request->purpose->value, $fetcher->requests()),
        );
        $this->fetcher->assertNothingFetched();
    }

    /**
     * The application's fetcher, sending through the handler given in place of
     * the network, built as the container builds it.
     *
     * @param  \GuzzleHttp\Handler\MockHandler  $handler
     * @return \Tests\Integration\Examples\OutboundRequests\ProxiedFetcher
     */
    private function proxiedFetcher(MockHandler $handler): ProxiedFetcher
    {
        config()->set('services.egress.proxy', self::PROXY);

        return app()->make(ProxiedFetcher::class, ['handler' => $handler]);
    }

    /**
     * The record type a `dig` lookup asks for: the fifth part of its command.
     *
     * @param  \Illuminate\Process\PendingProcess  $process
     * @return string
     */
    private static function recordType(PendingProcess $process): string
    {
        $command = (array) $process->command;

        return is_string($command[4] ?? null) ? $command[4] : '';
    }

    /**
     * Lay the guide's published configuration over the package's, key by key,
     * as Laravel merges a published file with a package's.
     *
     * @return void
     */
    private function publishConfiguration(): void
    {
        /** @var array<string, mixed> $published */
        $published = require __DIR__ . '/config/sso.php';

        /** @var array<string, mixed> $package */
        $package = config('sso');

        config()->set('sso', array_replace($package, $published));
    }
}
