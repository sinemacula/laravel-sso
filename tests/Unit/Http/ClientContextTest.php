<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Http\ClientContext;

/**
 * Unit tests for the client context, read from a request or built from plain
 * values: the same rules hold either way, so no instance holds an unsafe IP
 * address or user agent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClientContext::class)]
final class ClientContextTest extends TestCase
{
    /**
     * Rows of `[remote address, kept IP address]`.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideRemoteAddresses(): iterable
    {
        yield from [
            'IPv4'                   => ['203.0.113.7', '203.0.113.7'],
            'IPv6'                   => ['2001:db8::1', '2001:db8::1'],
            'IPv4-mapped IPv6'       => ['::ffff:203.0.113.7', '::ffff:203.0.113.7'],
            'longest, 45 characters' => ['0000:0000:0000:0000:0000:ffff:255.255.255.255', '0000:0000:0000:0000:0000:ffff:255.255.255.255'],
            'not an address'         => ['not-an-ip', null],
            'address with a port'    => ['203.0.113.7:443', null],
            'empty'                  => ['', null],
            'missing'                => [null, null],
        ];
    }

    /**
     * Only a valid IPv4 or IPv6 address read from a request is kept; anything
     * else is `null`.
     *
     * @param  ?string  $remoteAddress
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideRemoteAddresses')]
    public function testFromRequestKeepsOnlyAValidIpAddress(?string $remoteAddress, ?string $expected): void
    {
        $request = Request::create('/', 'GET', [], [], [], $remoteAddress === null ? [] : ['REMOTE_ADDR' => $remoteAddress]);

        if ($remoteAddress === null) {
            $request->server->remove('REMOTE_ADDR');
        }

        self::assertSame($expected, ClientContext::fromRequest($request)->ip);
    }

    /**
     * Rows of `[user agent, kept user agent]`.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideUserAgents(): iterable
    {
        yield from [
            'plain'                       => ['Mozilla/5.0', 'Mozilla/5.0'],
            'NUL bytes removed'           => ["Mozilla\0/5.0\0", 'Mozilla/5.0'],
            'invalid UTF-8 replaced'      => ["Agent \xC3\x28 \xFF", 'Agent ?( ?'],
            'controls removed'            => ["Agent\x1b/\t1.0\x7f\u{0085}", 'Agent/1.0'],
            'bidirectional controls'      => ["Agent\u{202E}/1.0\u{2066}", 'Agent/1.0'],
            'removed before the cut'      => [str_repeat("\t", 512) . 'Mozilla/5.0', 'Mozilla/5.0'],
            'exactly 512 characters'      => [str_repeat('é', 512), str_repeat('é', 512)],
            'over 512 characters cut'     => [str_repeat('é', 513), str_repeat('é', 512)],
            'cut after cleaning, by char' => ["\0" . str_repeat('日', 600), str_repeat('日', 512)],
            'empty'                       => ['', null],
            'only NUL bytes'              => ["\0\0", null],
            'missing'                     => [null, null],
        ];
    }

    /**
     * A user agent read from a request has invalid UTF-8 replaced and its
     * control and bidirectional characters removed, and is then cut to 512
     * characters (not bytes); one empty after cleaning, or not sent, is `null`.
     *
     * @param  ?string  $header
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideUserAgents')]
    public function testFromRequestCleansTheUserAgent(?string $header, ?string $expected): void
    {
        $request = Request::create('/', 'GET', [], [], [], $header === null ? [] : ['HTTP_USER_AGENT' => $header]);

        if ($header === null) {
            $request->headers->remove('User-Agent');
        }

        self::assertSame($expected, ClientContext::fromRequest($request)->userAgent);
    }

    /**
     * An IP address handed to the constructor is kept only when it is valid, as
     * one read from a request is.
     *
     * @param  ?string  $ip
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideRemoteAddresses')]
    public function testTheConstructorKeepsOnlyAValidIpAddress(?string $ip, ?string $expected): void
    {
        self::assertSame($expected, (new ClientContext($ip, 'Example/1.0'))->ip);
    }

    /**
     * A user agent handed to the constructor is cleaned as one read from a
     * request is.
     *
     * @param  ?string  $userAgent
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideUserAgents')]
    public function testTheConstructorCleansTheUserAgent(?string $userAgent, ?string $expected): void
    {
        self::assertSame($expected, (new ClientContext('203.0.113.7', $userAgent))->userAgent);
    }

    /**
     * A request is read for both values at once: its IP address and its user
     * agent, each held to its rule.
     *
     * @return void
     */
    public function testFromRequestReadsTheAddressAndTheUserAgent(): void
    {
        $client = ClientContext::fromRequest(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => "Example\0/2.0"]));

        self::assertSame(['198.51.100.9', 'Example/2.0'], [$client->ip, $client->userAgent]);
    }

    /**
     * The context of work with no client, as the console, a queued job or the
     * schedule builds it, holds neither value.
     *
     * @return void
     */
    public function testTheBackgroundValueHoldsNoClient(): void
    {
        $client = new ClientContext(null, null);

        self::assertNull($client->ip);
        self::assertNull($client->userAgent);
    }
}
