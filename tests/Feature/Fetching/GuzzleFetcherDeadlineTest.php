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
 * Feature tests for the default fetcher's deadline: the timeout is one budget
 * for the whole fetch, spent by every lookup and every hop, redirects included;
 * each transfer is given only what is left of it; and a lookup or hop that
 * leaves none fails the fetch as `timeout`, never fetched (SSO-2.9). Time
 * passes only on the test's own monotonic clock, moved by the lookup and the
 * mock handler, and nothing touches the network.
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
     * Start each test at nanosecond zero with an empty log and a one-second
     * connect timeout under a ten-second timeout.
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
     * A system lookup that takes longer than the whole timeout, and cannot be
     * cut short, fails the fetch as `timeout` once it returns: nothing is sent,
     * whatever it answered.
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
     * Less than a millisecond left is no time at all: cURL would read a timeout
     * of `0` as none.
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
     * Time that passes between the check straight after the lookup and the
     * transfer, leaving less than a millisecond, fails the fetch as `timeout`:
     * the transfer is never sent with a cap of `0`, which cURL reads as none,
     * and never answers `fetched`.
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
     * A redirect that finds less than a millisecond left by the time it would
     * be sent fails the fetch as `timeout` too, without sending it.
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
     * Rows of `[lookup nanoseconds, timeout, connect timeout]`: how long the
     * lookup took and the time caps the transfer is then given, in seconds.
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
     * The transfer is given only what the lookup left of the timeout, and its
     * connect timeout is capped to the same.
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
     * An IP literal is never resolved, so its transfer is given the whole
     * timeout.
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
     * Redirects share the one budget: each hop is given what the hops before it
     * left, not a fresh timeout of its own.
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
     * A hop that spends the rest of the budget ends the fetch at its redirect
     * as `timeout`: the next host is neither resolved nor asked.
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
     * A redirect's own lookup spends the shared budget too: one that runs past
     * the deadline fails the fetch as `timeout` without sending the redirect.
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
     * A transfer that fails once the deadline has passed, as cURL's own timeout
     * does, fails as `timeout`; one that fails within it stays `transfer`.
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
     * Build a fetcher over a mock handler answering with the responses in turn,
     * each moving the test's clock on by the nanoseconds given, the resolver
     * given (a stub of the test's hosts by default), a capturing logger and the
     * test's monotonic clock.
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
