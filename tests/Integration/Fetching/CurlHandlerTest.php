<?php

declare(strict_types = 1);

namespace Tests\Integration\Fetching;

use GuzzleHttp\Handler\CurlFactory;
use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\Handler\StreamHandler;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Http\Message\RequestInterface;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Fetching\AddressPolicy;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetcherSettings;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use Tests\Fixtures\Fetching\StubHostResolver;
use Tests\TestCase;

/**
 * Integration tests for the default fetcher's transport: resolved from the
 * container it sends through Guzzle's cURL handler and never PHP streams; it
 * refuses to be built without `ext-curl` rather than fall back; it refuses a
 * refused address before any connection is attempted; and the options it sends
 * are ones the installed Guzzle's cURL layer accepts (SSO-2.9). No request
 * leaves the process: the last test builds cURL handles without running them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuzzleFetcher::class)]
final class CurlHandlerTest extends TestCase
{
    /**
     * The contract resolves to the default fetcher, on Guzzle's cURL handler,
     * with no handler injected: never the stream handler, and never one Guzzle
     * would choose.
     *
     * @return void
     */
    public function testTheContainerGivesTheFetcherOnTheCurlHandler(): void
    {
        $fetcher = $this->app?->make(Fetcher::class);

        self::assertInstanceOf(GuzzleFetcher::class, $fetcher);

        $handler = (new \ReflectionProperty(GuzzleFetcher::class, 'handler'))->getValue($fetcher);

        self::assertInstanceOf(CurlHandler::class, $handler);
        self::assertNotInstanceOf(StreamHandler::class, $handler);
    }

    /**
     * A refused literal and a name resolving to a refused address are refused
     * before any connection is attempted, by the real cURL handler: the literal
     * is never resolved.
     *
     * @return void
     */
    public function testRefusesARefusedAddressWithoutConnecting(): void
    {
        $resolver = new StubHostResolver(['localhost' => ['127.0.0.1'], 'metadata.example.net' => ['169.254.169.254']]);
        $fetcher  = $this->fetcher($resolver);

        self::assertSame(FetchStatus::REFUSED, $fetcher->fetch(FetchRequest::metadata('https://127.0.0.1/'))->status);
        self::assertSame([], $resolver->lookups());

        self::assertSame(FetchStatus::REFUSED, $fetcher->fetch(FetchRequest::metadata('https://localhost/'))->status);
        self::assertSame(FetchStatus::REFUSED, $fetcher->fetch(FetchRequest::metadata('https://metadata.example.net/latest/meta-data/'))->status);
        self::assertSame(['localhost', 'metadata.example.net'], $resolver->lookups());
    }

    /**
     * Without `ext-curl`, and with no handler injected, the fetcher refuses to
     * be built rather than fall back to PHP streams.
     *
     * @return void
     */
    public function testRefusesToBeBuiltWithoutCurl(): void
    {
        $settings = new FetcherSettings(config());

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The outbound fetcher needs the PHP extension `curl`');

        new GuzzleFetcher($settings, new AddressPolicy($settings), new Logger('sso'), new StubHostResolver, null, static fn (): bool => false);
    }

    /**
     * Every option the fetcher sends, for every purpose and credential, is
     * accepted by the installed Guzzle's cURL layer: each request is turned
     * into a cURL handle by Guzzle's own factory, and the handle released
     * without being run, so an option Guzzle refuses (as Guzzle 8 refuses the
     * cURL options it manages itself) fails here instead of on every real
     * request.
     *
     * @return void
     */
    public function testSendsOptionsTheCurlLayerAccepts(): void
    {
        $built   = new \ArrayObject;
        $factory = new CurlFactory(1);

        $handler = static function (RequestInterface $request, array $options) use ($factory, $built): PromiseInterface {
            $factory->release($factory->create($request, $options));

            $built->append($request->getUri()->getHost());

            return Create::promiseFor(new Response(200, [], 'ok'));
        };

        $settings = new FetcherSettings(config());
        $resolver = new StubHostResolver(['idp.example.com' => ['93.184.216.34'], 'idp6.example.com' => ['2606:4700:4700::1111']]);
        $fetcher  = new GuzzleFetcher($settings, new AddressPolicy($settings), new Logger('sso'), $resolver, $handler);

        $requests = [
            FetchRequest::metadata('https://idp.example.com/metadata'),
            FetchRequest::discovery('https://idp6.example.com:8443/.well-known/openid-configuration'),
            FetchRequest::jwks('https://93.184.216.34/jwks'),
            FetchRequest::token('https://idp.example.com/token', ['grant_type' => 'authorization_code', 'code' => 'c'], FetchCredentials::clientSecretBasic('client', 'secret')),
            FetchRequest::token('https://idp.example.com/token', ['grant_type' => 'authorization_code', 'code' => 'c'], FetchCredentials::clientSecretPost('client', 'secret')),
            FetchRequest::userInfo('https://idp.example.com/userinfo', FetchCredentials::accessToken('token')),
        ];

        foreach ($requests as $request) {
            self::assertTrue($fetcher->fetch($request)->isFetched(), $request->purpose->value . ' was not accepted.');
        }

        self::assertCount(count($requests), $built);
    }

    /**
     * The default fetcher over the stub resolver, on the real cURL handler.
     *
     * @param  \Tests\Fixtures\Fetching\StubHostResolver  $resolver
     * @return \SineMacula\Laravel\Sso\Fetching\GuzzleFetcher
     */
    private function fetcher(StubHostResolver $resolver): GuzzleFetcher
    {
        $settings = new FetcherSettings(config());

        return new GuzzleFetcher($settings, new AddressPolicy($settings), new Logger('sso'), $resolver);
    }
}
