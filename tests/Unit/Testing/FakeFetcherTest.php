<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;

/**
 * Unit tests for the fake fetcher: it answers each URL with the response given
 * for it, exactly, or with what a closure builds from the request; it records
 * every request in order; a stray request throws naming its URL; and its
 * assertions pass and fail as they say.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeFetcher::class)]
final class FakeFetcherTest extends TestCase
{
    /** @var string The metadata URL in the tests. */
    private const string METADATA = 'https://idp.example.com/metadata';

    /** @var string The JWKS URL in the tests. */
    private const string JWKS = 'https://idp.example.com/jwks';

    /**
     * The fake is a fetcher, so it binds in place of the package's.
     *
     * @return void
     */
    public function testIsAFetcher(): void
    {
        self::assertInstanceOf(Fetcher::class, new FakeFetcher);
    }

    /**
     * Each URL is answered with its own response, and `respond()` returns the
     * fake for chaining.
     *
     * @return void
     */
    public function testRespondsByUrl(): void
    {
        $metadata = FetchResult::fetched(200, [], '<EntityDescriptor/>');
        $jwks     = FetchResult::failed();
        $fetcher  = new FakeFetcher;

        self::assertSame($fetcher, $fetcher->respond(self::METADATA, $metadata));
        self::assertSame($fetcher, $fetcher->respond(self::JWKS, $jwks));

        self::assertSame($metadata, $fetcher->fetch(FetchRequest::metadata(self::METADATA)));
        self::assertSame($jwks, $fetcher->fetch(FetchRequest::jwks(self::JWKS)));
        self::assertSame($metadata, $fetcher->fetch(FetchRequest::discovery(self::METADATA)));
    }

    /**
     * A URL is matched exactly: another case, a trailing slash or a query is
     * another URL.
     *
     * @return void
     */
    public function testMatchesTheUrlExactly(): void
    {
        $fetcher = (new FakeFetcher)->respond(self::METADATA, FetchResult::refused());

        foreach (['https://IDP.example.com/metadata', self::METADATA . '/', self::METADATA . '?v=1'] as $url) {
            try {
                $fetcher->fetch(FetchRequest::metadata($url));
                self::fail("{$url} was answered.");
            } catch (\LogicException $exception) {
                self::assertStringContainsString($url, $exception->getMessage());
            }
        }
    }

    /**
     * A later response to the same URL replaces an earlier one.
     *
     * @return void
     */
    public function testALaterResponseReplacesAnEarlierOne(): void
    {
        $later   = FetchResult::fetched(200, [], 'later');
        $fetcher = (new FakeFetcher)
            ->respond(self::METADATA, FetchResult::fetched(200, [], 'earlier'))
            ->respond(self::METADATA, $later);

        self::assertSame($later, $fetcher->fetch(FetchRequest::metadata(self::METADATA)));
    }

    /**
     * A closure response is called with the request each time, and its result
     * is the answer.
     *
     * @return void
     */
    public function testBuildsAResponseWithAClosure(): void
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Fetching\FetchRequest> $seen */
        $seen    = new \ArrayObject;
        $fetcher = (new FakeFetcher)->respond(self::METADATA, static function (FetchRequest $request) use ($seen): FetchResult {
            $seen->append($request);

            return FetchResult::fetched(200, [], $request->purpose->value);
        });

        $first  = FetchRequest::metadata(self::METADATA);
        $second = FetchRequest::userInfo(self::METADATA, FetchCredentials::accessToken('token'));

        self::assertSame('metadata', $fetcher->fetch($first)->body());
        self::assertSame('userinfo', $fetcher->fetch($second)->body());
        self::assertSame([$first, $second], $seen->getArrayCopy());
    }

    /**
     * A request that carries its own cap fails when the body it would be
     * answered with is longer, and is answered at the cap; a request with none
     * is answered whatever the body's length.
     *
     * @return void
     */
    public function testARequestsOwnCapHoldsTheBody(): void
    {
        $fetcher = (new FakeFetcher)->respond(self::METADATA, FetchResult::fetched(200, [], str_repeat('a', 10)));

        self::assertSame(FailureReason::FETCH_FAILED, $fetcher->fetch(FetchRequest::metadata(self::METADATA, 9))->reason);
        self::assertSame(10, strlen((string) $fetcher->fetch(FetchRequest::metadata(self::METADATA, 10))->body()));
        self::assertSame(10, strlen((string) $fetcher->fetch(FetchRequest::metadata(self::METADATA))->body()));
        self::assertCount(3, $fetcher->requests());
    }

    /**
     * Every request is recorded, in order, nothing before the first.
     *
     * @return void
     */
    public function testRecordsEveryRequestInOrder(): void
    {
        $fetcher = (new FakeFetcher)
            ->respond(self::METADATA, FetchResult::fetched(200, [], 'ok'))
            ->respond(self::JWKS, FetchResult::fetched(200, [], '{}'));

        self::assertSame([], $fetcher->requests());

        $metadata = FetchRequest::metadata(self::METADATA);
        $jwks     = FetchRequest::jwks(self::JWKS);

        $fetcher->fetch($metadata);
        $fetcher->fetch($jwks);
        $fetcher->fetch($metadata);

        self::assertSame([$metadata, $jwks, $metadata], $fetcher->requests());
    }

    /**
     * A request to a URL with no response throws a `LogicException` naming the
     * URL, so a stray request fails the test; it is still recorded.
     *
     * @return void
     */
    public function testAStrayRequestThrows(): void
    {
        $fetcher = new FakeFetcher;
        $request = FetchRequest::discovery('https://stray.example.com/.well-known/openid-configuration');

        try {
            $fetcher->fetch($request);
            self::fail('A stray request was answered.');
        } catch (\LogicException $exception) {
            self::assertSame('FakeFetcher has no response for [https://stray.example.com/.well-known/openid-configuration].', $exception->getMessage());
        }

        self::assertSame([$request], $fetcher->requests());
    }

    /**
     * `assertFetched()` passes for a URL fetched, with or without its purpose.
     *
     * @return void
     */
    public function testAssertFetchedPassesForAFetchedUrl(): void
    {
        $fetcher = (new FakeFetcher)->respond(self::JWKS, FetchResult::fetched(200, [], '{}'));

        $fetcher->fetch(FetchRequest::jwks(self::JWKS));

        $fetcher->assertFetched(self::JWKS);
        $fetcher->assertFetched(self::JWKS, FetchPurpose::JWKS);
    }

    /**
     * `assertFetched()` fails for a URL not fetched, naming it.
     *
     * @return void
     */
    public function testAssertFetchedFailsForAnotherUrl(): void
    {
        $fetcher = (new FakeFetcher)->respond(self::JWKS, FetchResult::fetched(200, [], '{}'));

        $fetcher->fetch(FetchRequest::jwks(self::JWKS));

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Expected [' . self::METADATA . '] to be fetched; it was not.');

        $fetcher->assertFetched(self::METADATA);
    }

    /**
     * `assertFetched()` fails for a URL fetched for another purpose, naming the
     * purpose expected.
     *
     * @return void
     */
    public function testAssertFetchedFailsForAnotherPurpose(): void
    {
        $fetcher = (new FakeFetcher)->respond(self::JWKS, FetchResult::fetched(200, [], '{}'));

        $fetcher->fetch(FetchRequest::jwks(self::JWKS));

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Expected [' . self::JWKS . ' for discovery] to be fetched; it was not.');

        $fetcher->assertFetched(self::JWKS, FetchPurpose::DISCOVERY);
    }

    /**
     * `assertFetched()` fails when nothing was fetched.
     *
     * @return void
     */
    public function testAssertFetchedFailsWhenNothingWasFetched(): void
    {
        $this->expectException(AssertionFailedError::class);

        (new FakeFetcher)->assertFetched(self::METADATA);
    }

    /**
     * `assertNothingFetched()` passes before any request.
     *
     * @return void
     */
    public function testAssertNothingFetchedPassesBeforeAnyRequest(): void
    {
        (new FakeFetcher)->respond(self::METADATA, FetchResult::refused())->assertNothingFetched();
    }

    /**
     * `assertNothingFetched()` fails after a request, even a stray one.
     *
     * @return void
     */
    public function testAssertNothingFetchedFailsAfterARequest(): void
    {
        $fetcher = new FakeFetcher;

        try {
            $fetcher->fetch(FetchRequest::metadata(self::METADATA));
        } catch (\LogicException) {
            // The stray request is still recorded, which is what is asserted
        }

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Expected nothing to be fetched.');

        $fetcher->assertNothingFetched();
    }
}
