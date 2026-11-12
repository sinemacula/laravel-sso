<?php

declare(strict_types = 1);

namespace Tests\Integration\Fetching;

use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\Promise\PromiseInterface;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Http\Message\RequestInterface;
use SineMacula\Laravel\Sso\Fetching\AddressPolicy;
use SineMacula\Laravel\Sso\Fetching\CappedSink;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Fetching\FetcherSettings;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use Tests\Fixtures\Fetching\StubHostResolver;
use Tests\Fixtures\Fetching\TlsServer;
use Tests\TestCase;

/**
 * Integration tests of the default fetcher against a local HTTPS server. Only
 * the pinned address is rewritten; verification stays on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuzzleFetcher::class)]
#[CoversClass(CappedSink::class)]
final class TlsTransportTest extends TestCase
{
    /** @var string The host every request names, which DNS never resolves. */
    private const string HOST = 'idp.invalid';

    /** @var string The public address the stub resolver answers for the host. */
    private const string ADDRESS = '93.184.216.34';

    /** @var \Monolog\Handler\TestHandler What the fetcher logged. */
    private TestHandler $log;

    /**
     * Skip where the transport or the test server cannot run.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (!extension_loaded('curl') || !extension_loaded('openssl')) {
            self::markTestSkipped('A real TLS transfer needs ext-curl and ext-openssl.');
        }

        $this->log = new TestHandler;
    }

    /**
     * The connection goes to the pinned address with the name verified and
     * sent.
     *
     * @return void
     *
     * @throws \JsonException
     * @throws \Random\RandomException
     */
    public function testConnectsToThePinnedAddress(): void
    {
        $server = TlsServer::start('ok', self::HOST);
        $result = $this->fetch($server, trusted: true);
        $report = $server->finish();

        self::assertTrue($result->isFetched(), (string) json_encode($this->log->getRecords()));
        self::assertSame(200, $result->statusCode);
        self::assertSame('ok', $result->body());
        self::assertTrue($report['handshake']);
        self::assertSame('GET /metadata HTTP/1.1', $report['request']);
        self::assertSame(self::HOST . ':' . $server->port(), $report['host']);
    }

    /**
     * An untrusted certificate fails the fetch before the request is sent.
     *
     * @return void
     *
     * @throws \JsonException
     * @throws \Random\RandomException
     */
    public function testAnUntrustedCertificateFails(): void
    {
        $server = TlsServer::start('ok', self::HOST);
        $result = $this->fetch($server, trusted: false);
        $report = $server->finish();

        self::assertSame(FetchStatus::FAILED, $result->status);
        self::assertSame('transfer', $this->loggedContext()['cause'] ?? null);
        self::assertNull($report['request']);
        self::assertSame(0, $report['sent']);
    }

    /**
     * A trusted certificate for another name fails the fetch.
     *
     * @return void
     *
     * @throws \JsonException
     * @throws \Random\RandomException
     */
    public function testACertificateForAnotherNameFails(): void
    {
        $server = TlsServer::start('ok', 'other.invalid');
        $result = $this->fetch($server, trusted: true);
        $report = $server->finish();

        self::assertSame(FetchStatus::FAILED, $result->status);
        self::assertSame('transfer', $this->loggedContext()['cause'] ?? null);
        self::assertNull($report['request']);
        self::assertSame(0, $report['sent']);
    }

    /**
     * A body past the cap is aborted during the transfer.
     *
     * @return void
     *
     * @throws \JsonException
     * @throws \Random\RandomException
     */
    public function testABodyPastTheCapIsAbortedDuringTheTransfer(): void
    {
        config()->set('sso.fetcher.max_response_bytes', 1024);

        $server = TlsServer::start('stream', self::HOST);
        $result = $this->fetch($server, trusted: true);
        $report = $server->finish();

        self::assertSame(FetchStatus::FAILED, $result->status);
        self::assertSame('too_large', $this->loggedContext()['cause'] ?? null);
        self::assertTrue($report['handshake']);
        self::assertFalse($report['complete']);
        self::assertLessThan(TlsServer::STREAMED_BYTES, $report['sent']);
    }

    /**
     * Fetch the server's metadata through the real cURL handler, trusting it
     * when asked.
     *
     * @param  \Tests\Fixtures\Fetching\TlsServer  $server
     * @param  bool  $trusted
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     */
    private function fetch(TlsServer $server, bool $trusted): FetchResult
    {
        $curl   = new CurlHandler;
        $pinned = sprintf('%s:%d:%s', self::HOST, $server->port(), self::ADDRESS);

        $handler = static function (RequestInterface $request, array $options) use ($curl, $server, $trusted, $pinned): PromiseInterface {
            /** @var array<int, mixed> $curlOptions */
            $curlOptions = $options['curl'] ?? [];

            self::assertSame([$pinned], $curlOptions[CURLOPT_RESOLVE] ?? null);
            self::assertTrue($options['verify'] ?? null);

            $curlOptions[CURLOPT_RESOLVE] = [sprintf('%s:%d:127.0.0.1', self::HOST, $server->port())];

            $options['curl'] = $curlOptions;

            if ($trusted) {
                $options['verify'] = $server->certificate();
            }

            return $curl($request, $options);
        };

        $settings = new FetcherSettings(config());
        $resolver = new StubHostResolver([self::HOST => [self::ADDRESS]]);
        $fetcher  = new GuzzleFetcher($settings, new AddressPolicy($settings), new Logger('sso', [$this->log]), $resolver, $handler);

        return $fetcher->fetch(FetchRequest::metadata(sprintf('https://%s:%d/metadata', self::HOST, $server->port())));
    }

    /**
     * The context of the last warning logged, `[]` when none was.
     *
     * @return array<string, mixed>
     */
    private function loggedContext(): array
    {
        $records = $this->log->getRecords();

        return $records === [] ? [] : $records[array_key_last($records)]->context;
    }
}
