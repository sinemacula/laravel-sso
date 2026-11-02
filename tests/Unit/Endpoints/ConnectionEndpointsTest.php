<?php

declare(strict_types = 1);

namespace Tests\Unit\Endpoints;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;
use SineMacula\Laravel\Sso\Endpoints\Enums\Endpoint;

/**
 * Unit tests for a connection's endpoints: each kept exactly as built, read by
 * endpoint, and refused, naming the endpoint, unless it is an absolute https
 * URL or http on a loopback address with no user information, fragment or
 * wildcard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionEndpoints::class)]
#[CoversClass(Endpoint::class)]
final class ConnectionEndpointsTest extends TestCase
{
    /**
     * Each URL is kept exactly, and read by its endpoint.
     *
     * @return void
     */
    public function testKeepsEachUrl(): void
    {
        $endpoints = new ConnectionEndpoints(
            'https://sp.example.com/acs',
            'https://sp.example.com/cb?c=1',
            'https://sp.example.com/entity',
            'http://127.0.0.1:8000/md',
            'https://sp.example.com/jwks',
        );

        self::assertSame('https://sp.example.com/acs', $endpoints->assertionConsumerService);
        self::assertSame('https://sp.example.com/cb?c=1', $endpoints->callback);
        self::assertSame('https://sp.example.com/entity', $endpoints->entityId);
        self::assertSame('http://127.0.0.1:8000/md', $endpoints->metadata);
        self::assertSame('https://sp.example.com/jwks', $endpoints->jwks);
        self::assertSame('https://sp.example.com/acs', $endpoints->url(Endpoint::ASSERTION_CONSUMER_SERVICE));
        self::assertSame('https://sp.example.com/cb?c=1', $endpoints->url(Endpoint::CALLBACK));
        self::assertSame('http://127.0.0.1:8000/md', $endpoints->url(Endpoint::METADATA));
        self::assertSame('https://sp.example.com/jwks', $endpoints->url(Endpoint::JWKS));
        self::assertSame([
            'assertion_consumer_service' => 'https://sp.example.com/acs',
            'callback'                   => 'https://sp.example.com/cb?c=1',
            'entity_id'                  => 'https://sp.example.com/entity',
            'metadata'                   => 'http://127.0.0.1:8000/md',
            'jwks'                       => 'https://sp.example.com/jwks',
        ], $endpoints->jsonSerialize());
        self::assertSame(['assertion_consumer_service', 'callback', 'metadata', 'jwks'], array_column(Endpoint::cases(), 'value'));
    }

    /**
     * Rows of `[position, url, key]`: a malformed URL in each position, and the
     * key it is refused under.
     *
     * @return iterable<string, array{0: int, 1: string, 2: string}>
     */
    public static function provideMalformedUrls(): iterable
    {
        yield 'a plain http assertion consumer service' => [0, 'http://sp.example.com/acs', 'endpoints.assertion_consumer_service'];
        yield 'a relative callback' => [1, '/cb', 'endpoints.callback'];
        yield 'an entity id with a fragment' => [2, 'https://sp.example.com/entity#x', 'endpoints.entity_id'];
        yield 'metadata with user information' => [3, 'https://user@sp.example.com/md', 'endpoints.metadata'];
        yield 'a wildcard' => [0, 'https://*.example.com/acs', 'endpoints.assertion_consumer_service'];
        yield 'a private-use scheme' => [1, 'com.example.app:/cb', 'endpoints.callback'];
        yield 'a plain http public JWKS URL' => [4, 'http://sp.example.com/jwks', 'endpoints.jwks'];
        yield 'a public JWKS URL with a wildcard' => [4, 'https://*.example.com/jwks', 'endpoints.jwks'];
        yield 'a public JWKS URL with a fragment' => [4, 'https://sp.example.com/jwks#x', 'endpoints.jwks'];
    }

    /**
     * Each malformed URL is refused naming its endpoint.
     *
     * @param  int  $position
     * @param  string  $url
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideMalformedUrls')]
    public function testRefusesAMalformedUrl(int $position, string $url, string $key): void
    {
        $urls            = ['https://sp.example.com/acs', 'https://sp.example.com/cb', 'https://sp.example.com/entity', 'https://sp.example.com/md', 'https://sp.example.com/jwks'];
        $urls[$position] = $url;

        $this->expectExceptionObject(new \InvalidArgumentException(
            "`{$key}` must be an absolute https URL (or http on 127.0.0.1 or [::1]) with no user information, fragment or wildcard.",
        ));

        new ConnectionEndpoints(...$urls);
    }
}
