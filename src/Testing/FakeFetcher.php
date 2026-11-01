<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;

/**
 * A fetcher for tests that answers each URL with the response the test gave it
 * and records every request, so a test of metadata, discovery, a JWKS, a token
 * or UserInfo request makes no network request (SSO-2.9).
 *
 * Bind it in place of the package's fetcher with
 * `$app->instance(Fetcher::class, $fetcher = new FakeFetcher())`, give each URL
 * its response with `respond()` (a `FetchResult`, or a closure that builds one
 * from the request), then assert what was fetched. A URL is matched exactly, as
 * the request carries it. A request to a URL with no response throws a
 * `LogicException` naming the URL, so a stray request fails the test rather
 * than passing unnoticed. It applies none of the default fetcher's checks:
 * those are the default fetcher's tests' to cover.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeFetcher implements Fetcher
{
    /** @var array<string, \Closure(\SineMacula\Laravel\Sso\Fetching\FetchRequest): \SineMacula\Laravel\Sso\Fetching\FetchResult|\SineMacula\Laravel\Sso\Fetching\FetchResult> The response to each URL. */
    private array $responses = [];

    /** @var list<\SineMacula\Laravel\Sso\Fetching\FetchRequest> Every request, in the order it was made. */
    private array $requests = [];

    /**
     * Answer every request to the URL with the response, or with what the
     * closure builds from the request; a later response to the same URL
     * replaces an earlier one.
     *
     * @param  string  $url
     * @param  \Closure(\SineMacula\Laravel\Sso\Fetching\FetchRequest): \SineMacula\Laravel\Sso\Fetching\FetchResult|\SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @return self
     */
    public function respond(string $url, \Closure|FetchResult $response): self
    {
        $this->responses[$url] = $response;

        return $this;
    }

    /**
     * Record the request and answer it with the response given for its URL.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     *
     * @throws \LogicException
     */
    #[\Override]
    public function fetch(FetchRequest $request): FetchResult
    {
        $this->requests[] = $request;

        if (!array_key_exists($request->url, $this->responses)) {
            throw new \LogicException(sprintf('FakeFetcher has no response for [%s].', $request->url));
        }

        $response = $this->responses[$request->url];

        return $response instanceof \Closure ? $response($request) : $response;
    }

    /**
     * Every request made, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Fetching\FetchRequest>
     */
    public function requests(): array
    {
        return $this->requests;
    }

    /**
     * Assert that the URL was fetched, for the purpose when one is given.
     *
     * @param  string  $url
     * @param  ?\SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose  $purpose
     * @return void
     */
    public function assertFetched(string $url, ?FetchPurpose $purpose = null): void
    {
        $matching = array_filter(
            $this->requests,
            static fn (FetchRequest $request): bool => $request->url === $url && ($purpose === null || $request->purpose === $purpose),
        );

        $expected = $purpose === null ? $url : sprintf('%s for %s', $url, $purpose->value);

        Assert::assertNotSame([], $matching, sprintf('Expected [%s] to be fetched; it was not.', $expected));
    }

    /**
     * Assert that nothing was fetched.
     *
     * @return void
     */
    public function assertNothingFetched(): void
    {
        $urls = array_map(static fn (FetchRequest $request): string => $request->url, $this->requests);

        Assert::assertSame([], $urls, 'Expected nothing to be fetched.');
    }
}
