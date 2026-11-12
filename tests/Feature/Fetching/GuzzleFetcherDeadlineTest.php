<?php

declare(strict_types = 1);

namespace Tests\Feature\Fetching;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\RequestInterface;
use SineMacula\Laravel\Sso\Contracts\HostResolver;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\AddressPolicy;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Fetching\FetcherSettings;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use SineMacula\Laravel\Sso\Fetching\SystemHostResolver;
use Tests\Fixtures\Fetching\StubHostResolver;
use Tests\TestCase;

/**
 * Feature tests for the default fetcher's single deadline. Time moves only on
 * the test's monotonic clock; nothing touches the network.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuzzleFetcher::class)]
final class GuzzleFetcherDeadlineTest extends TestCase
{
    /** @var string The metadata URL fetched. */
    private const string URL = 'https://idp.example.com/metadata';

    /** @var string The public address the identity provider's host resolves to. */
    private const string ADDRESS = '93.184.216.34';

    /** @var int The nanoseconds in a millisecond. */
    private const int MILLISECOND = 1000000;

    /** @var int The nanoseconds in a second. */
    private const int SECOND = 1000000000;

    /** @var array<string, list<string>> The hosts the stub resolver knows. */
    private const array HOSTS = [
        'idp.example.com' => [self::ADDRESS],
        'cdn.example.net' => ['151.101.1.1'],
        'www.example.org' => ['2606:4700:4700::1111'],
    ];

    /** @var int The test's monotonic clock, in nanoseconds. */
    private int $now = 0;

    /** @var int The nanoseconds the test's clock moves on after each read, as a loaded worker's would between two of them. */
    private int $drift = 0;

    /** @var list<array{request: \Psr\Http\Message\RequestInterface, options: array<string, mixed>}> Every request the mock handler received, with its options. */
    private array $sent = [];

    /** @var \Monolog\Handler\TestHandler What the fetcher logged. */
    private TestHandler $log;

    /**
     * Start at nanosecond zero with a one-second connect timeout under a
     * ten-second timeout.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now   = 0;
        $this->drift = 0;
        $this->sent  = [];
        $this->log   = new TestHandler;

        config()->set('sso.fetcher.timeout_seconds', 10);
        config()->set('sso.fetcher.connect_timeout_seconds', 5);
    }

    /**
     * A system lookup that outlasts the timeout fails the fetch as `timeout`,
     * sending nothing.
     *
     * @return void
     */
    public function testASlowResolutionOverTheBudgetFailsAsATimeout(): void
    {
        config()->set('sso.fetcher.timeout_seconds', 1);

        $resolver = new SystemHostResolver(function (): array {
            $this->now += 1200 * self::MILLISECOND;

            return [['type' => 'A', 'ip' => self::ADDRESS]];
        });

        $result = $this->fetcher([new Response(200, [], 'ok')], $resolver)->fetch(FetchRequest::metadata(self::URL));

        $this->assertTimedOut($result, 'idp.example.com');
        self::assertSame([], $this->sent);
    }

    /**
     * Less than a millisecond left is a timeout, since cURL reads `0` as no
     * timeout.
     *
     * @return void
     */
    public function testLessThanAMillisecondLeftAfterTheLookupIsATimeout(): void
    {
        $resolver = new SystemHostResolver(function (): array {
            $this->now += 10 * self::SECOND - self::MILLISECOND / 2;

            return [['type' => 'A', 'ip' => self::ADDRESS]];
        });

        $result = $this->fetcher([new Response(200, [], 'ok')], $resolver)->fetch(FetchRequest::metadata(self::URL));

        $this->assertTimedOut($result, 'idp.example.com');
        self::assertSame([], $this->sent);
    }

    /**
     * Time passing after the lookup check to under a millisecond is a timeout,
     * never a `0` cap.
     *
     * @return void
     */
    public function testTimePassingAfterTheLookupCheckIsATimeout(): void
    {
        $resolver = new SystemHostResolver(function (): array {
            $this->now += 10 * self::SECOND - 3 * self::MILLISECOND / 2;
            $this->drift = 6 * self::MILLISECOND                    / 10;

            return [['type' => 'A', 'ip' => self::ADDRESS]];
        });

        $result = $this->fetcher([new Response(200, [], 'ok')], $resolver)->fetch(FetchRequest::metadata(self::URL));

        $this->assertTimedOut($result, 'idp.example.com');
        self::assertSame([], $this->sent);
    }

    /**
     * A redirect with under a millisecond left is a timeout and is not sent.
     *
     * @return void
     */
    public function testTimePassingBeforeARedirectIsSentIsATimeout(): void
    {
        $resolver = new SystemHostResolver(function (string $host): array {
            if ($host === 'cdn.example.net') {
                $this->now += 5  * self::SECOND - 3 * self::MILLISECOND / 2;
                $this->drift = 6 * self::MILLISECOND                    / 10;
            }

            return [['type' => 'A', 'ip' => self::HOSTS[$host][0] ?? self::ADDRESS]];
        });

        $result = $this->fetcher([
            new Response(302, ['Location' => 'https://cdn.example.net/metadata']),
            new Response(200, [], '<EntityDescriptor/>'),
        ], $resolver, 5 * self::SECOND)->fetch(FetchRequest::metadata(self::URL));

        $this->assertTimedOut($result, 'cdn.example.net');
        self::assertCount(1, $this->sent);
    }

    /**
     * Rows of `[lookup nanoseconds, timeout, connect timeout]`, the caps in
     * seconds.
     *
     * @return iterable<string, array{int, float, float}>
     */
    public static function provideLookupTimes(): iterable
    {
        yield from [
            'an instant lookup'                      => [0, 10.0, 5.0],
            'a lookup leaving more than the connect' => [4250 * self::MILLISECOND, 5.75, 5.0],
            'a lookup leaving less than the connect' => [7 * self::SECOND, 3.0, 3.0],
            'a lookup leaving a millisecond'         => [10 * self::SECOND - self::MILLISECOND, 0.001, 0.001],
        ];
    }

    /**
     * The transfer gets only what the lookup left, with the connect timeout
     * capped to it.
     *
     * @param  int  $lookup
     * @param  float  $timeout
     * @param  float  $connectTimeout
     * @return void
     */
    #[DataProvider('provideLookupTimes')]
    public function testTheTransferIsGivenOnlyTheTimeLeft(int $lookup, float $timeout, float $connectTimeout): void
    {
        $resolver = new SystemHostResolver(function () use ($lookup): array {
            $this->now += $lookup;

            return [['type' => 'A', 'ip' => self::ADDRESS]];
        });

        $result = $this->fetcher([new Response(200, [], 'ok')], $resolver)->fetch(FetchRequest::metadata(self::URL));

        self::assertTrue($result->isFetched());
        self::assertCount(1, $this->sent);
        self::assertSame($timeout, $this->sent[0]['options']['timeout'] ?? null);
        self::assertSame($connectTimeout, $this->sent[0]['options']['connect_timeout'] ?? null);
    }

    /**
     * An IP literal is never resolved, so its transfer gets the whole timeout.
     *
     * @return void
     */
    public function testAnIpLiteralIsGivenTheWholeTimeout(): void
    {
        $result = $this->fetcher([new Response(200, [], 'ok')])->fetch(FetchRequest::metadata('https://' . self::ADDRESS . '/metadata'));

        self::assertTrue($result->isFetched());
        self::assertSame(10.0, $this->sent[0]['options']['timeout'] ?? null);
        self::assertSame(5.0, $this->sent[0]['options']['connect_timeout'] ?? null);
    }

    /**
     * Redirects share one budget; each hop gets what the hops before it left.
     *
     * @return void
     */
    public function testTheBudgetIsSharedAcrossRedirects(): void
    {
        $result = $this->fetcher([
            new Response(302, ['Location' => 'https://cdn.example.net/metadata']),
            new Response(302, ['Location' => 'https://www.example.org/metadata']),
            new Response(200, [], '<EntityDescriptor/>'),
        ], spent: 3 * self::SECOND)->fetch(FetchRequest::metadata(self::URL));

        self::assertTrue($result->isFetched());
        self::assertSame('<EntityDescriptor/>', $result->body());
        self::assertSame([10.0, 7.0, 4.0], array_map(static fn (array $sent): mixed => $sent['options']['timeout'] ?? null, $this->sent));
        self::assertSame([5.0, 5.0, 4.0], array_map(static fn (array $sent): mixed => $sent['options']['connect_timeout'] ?? null, $this->sent));
    }

    /**
     * A hop that spends the budget ends the fetch as `timeout` before the next
     * host is resolved.
     *
     * @return void
     */
    public function testAHopThatSpendsTheBudgetEndsTheFetchAsATimeout(): void
    {
        $resolver = new StubHostResolver(self::HOSTS);

        $result = $this->fetcher([
            new Response(302, ['Location' => 'https://cdn.example.net/metadata']),
            new Response(200, [], '<EntityDescriptor/>'),
        ], $resolver, 10 * self::SECOND)->fetch(FetchRequest::metadata(self::URL));

        $this->assertTimedOut($result, 'cdn.example.net');
        self::assertCount(1, $this->sent);
        self::assertSame(['idp.example.com'], $resolver->lookups());
    }

    /**
     * A redirect's slow lookup spends the shared budget and fails as `timeout`.
     *
     * @return void
     */
    public function testASlowResolutionOfARedirectFailsAsATimeout(): void
    {
        $resolver = new SystemHostResolver(function (string $host): array {
            $this->now += $host === 'cdn.example.net' ? 6 * self::SECOND : 0;

            return [['type' => 'A', 'ip' => self::HOSTS[$host][0] ?? self::ADDRESS]];
        });

        $result = $this->fetcher([
            new Response(302, ['Location' => 'https://cdn.example.net/metadata']),
            new Response(200, [], '<EntityDescriptor/>'),
        ], $resolver, 5 * self::SECOND)->fetch(FetchRequest::metadata(self::URL));

        $this->assertTimedOut($result, 'cdn.example.net');
        self::assertCount(1, $this->sent);
    }

    /**
     * A transfer failing past the deadline is `timeout`; one failing within it
     * is `transfer`.
     *
     * @return void
     */
    public function testATransferFailingPastTheDeadlineIsATimeout(): void
    {
        $timedOut = new ConnectException('cURL error 28: Operation timed out', new Request('GET', self::URL));
        $result   = $this->fetcher([$timedOut], spent: 10 * self::SECOND)->fetch(FetchRequest::metadata(self::URL));

        $this->assertTimedOut($result, 'idp.example.com');
        self::assertSame(ConnectException::class, $this->log->getRecords()[0]->context['exception_class'] ?? null);

        $refused = new ConnectException('cURL error 7: Failed to connect', new Request('GET', self::URL));

        $this->fetcher([$refused], spent: self::SECOND)->fetch(FetchRequest::metadata(self::URL));

        self::assertSame('transfer', $this->log->getRecords()[0]->context['cause'] ?? null);
    }

    /**
     * A fetcher over a mock handler whose responses advance the test's clock by
     * the given nanoseconds.
     *
     * @param  list<\Psr\Http\Message\ResponseInterface|\Throwable>  $responses
     * @param  ?\SineMacula\Laravel\Sso\Contracts\HostResolver  $resolver
     * @param  int  $spent
     * @return \SineMacula\Laravel\Sso\Fetching\GuzzleFetcher
     */
    private function fetcher(array $responses, ?HostResolver $resolver = null, int $spent = 0): GuzzleFetcher
    {
        $mock = new MockHandler($responses);

        $this->sent = [];
        $this->log  = new TestHandler;

        $handler = function (RequestInterface $request, array $options) use ($mock, $spent): PromiseInterface {
            $this->sent[] = ['request' => $request, 'options' => $options];
            $this->now += $spent;

            return $mock($request, $options);
        };

        $settings = new FetcherSettings(config());

        return new GuzzleFetcher(
            $settings,
            new AddressPolicy($settings),
            new Logger('sso', [$this->log]),
            $resolver ?? new StubHostResolver(self::HOSTS),
            $handler,
            null,
            fn (): int => $this->read(),
        );
    }

    /**
     * The test's clock, moved on by the drift once read.
     *
     * @return int
     */
    private function read(): int
    {
        $now = $this->now;
        $this->now += $this->drift;

        return $now;
    }

    /**
     * Assert the fetch failed as `timeout` at the host, logged once.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $result
     * @param  string  $host
     * @return void
     */
    private function assertTimedOut(FetchResult $result, string $host): void
    {
        self::assertSame(FetchStatus::FAILED, $result->status);
        self::assertSame(FailureReason::FETCH_FAILED, $result->reason);
        self::assertNull($result->body());
        self::assertCount(1, $this->log->getRecords());
        self::assertSame('sso.fetch.failed', $this->log->getRecords()[0]->message);
        self::assertSame('timeout', $this->log->getRecords()[0]->context['cause'] ?? null);
        self::assertSame($host, $this->log->getRecords()[0]->context['host'] ?? null);
    }
}
