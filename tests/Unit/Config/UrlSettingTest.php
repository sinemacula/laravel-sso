<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Config\UrlSetting;

/**
 * Unit tests for the URL setting reader.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UrlSetting::class)]
final class UrlSettingTest extends TestCase
{
    /** @var string The key the tests read. */
    private const string KEY = 'sso.example.url';

    /**
     * Rows of `[value]`: web URLs, each accepted by both readers.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideWebUrls(): iterable
    {
        yield from [
            'https with a path'         => ['https://app.example.com/auth/sso/complete'],
            'https with a port'         => ['https://app.example.com:8443/complete'],
            'https with no path'        => ['https://app.example.com'],
            'http on the IPv4 loopback' => ['http://127.0.0.1:8000/complete'],
            'http on the IPv6 loopback' => ['http://[::1]:8000/complete'],
            'https with a query'        => ['https://app.example.com/complete?app=web'],
        ];
    }

    /**
     * A web URL is accepted as a web URL and as a redirect URI, unchanged.
     *
     * @param  string  $url
     * @return void
     */
    #[DataProvider('provideWebUrls')]
    public function testAcceptsAWebUrl(string $url): void
    {
        self::assertSame($url, UrlSetting::web(self::KEY, $url));
        self::assertSame($url, UrlSetting::redirect(self::KEY, $url));
    }

    /**
     * Rows of `[value]`: private-use schemes a native application registers.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function providePrivateUseUris(): iterable
    {
        yield from [
            'a single slash'    => ['com.example.app:/sso/complete'],
            'an authority'      => ['com.example.app://sso/complete'],
            'digits and dashes' => ['com.example-2.app:/complete'],
        ];
    }

    /**
     * A private-use scheme is a redirect URI, never a web URL.
     *
     * @param  string  $uri
     * @return void
     */
    #[DataProvider('providePrivateUseUris')]
    public function testAcceptsAPrivateUseSchemeAsARedirectOnly(string $uri): void
    {
        self::assertSame($uri, UrlSetting::redirect(self::KEY, $uri));

        $this->expectException(\InvalidArgumentException::class);

        UrlSetting::web(self::KEY, $uri);
    }

    /**
     * Rows of `[value]`: values neither reader accepts.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideRefusedValues(): iterable
    {
        yield from [
            'null'                      => [null],
            'an integer'                => [443],
            'an empty string'           => [''],
            'plain http'                => ['http://app.example.com/complete'],
            'http on localhost'         => ['http://localhost/complete'],
            'upper-case https'          => ['HTTPS://app.example.com/complete'],
            'https with no host'        => ['https:///complete'],
            'a relative path'           => ['/complete'],
            'a fragment'                => ['https://app.example.com/complete#code'],
            'a wildcard host'           => ['https://*.example.com/complete'],
            'a wildcard path'           => ['https://app.example.com/*'],
            'user information'          => ['https://user:pass@app.example.com/complete'],
            'a user name'               => ['https://user@app.example.com/complete'],
            'a space'                   => ['https://app.example.com/com plete'],
            'a trailing newline'        => ["https://app.example.com/complete\n"],
            'a backslash'               => ['https://app.example.com\@evil.example/'],
            'javascript'                => ['javascript:alert(1)'],
            'data'                      => ['data:text/html,hi'],
            'a scheme without a dot'    => ['myapp:/complete'],
            'an upper-case private use' => ['Com.Example.App:/complete'],
            'too long'                  => ['https://app.example.com/' . str_repeat('a', 2048)],
        ];
    }

    /**
     * A value neither reader accepts fails, naming the key and never the value.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testRefusesWhatNeitherAccepts(mixed $value): void
    {
        foreach ([UrlSetting::web(...), UrlSetting::redirect(...)] as $reader) {
            try {
                $reader(self::KEY, $value);

                self::fail('Expected the value to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringStartsWith('`sso.example.url` must be ', $exception->getMessage());
                self::assertStringNotContainsString('example.com/', $exception->getMessage());
            }
        }
    }

    /**
     * A web URL read without a query refuses one, and says so.
     *
     * @return void
     */
    public function testAWebUrlMayBeReadWithoutAQuery(): void
    {
        self::assertSame('https://api.example.com/v1', UrlSetting::web(self::KEY, 'https://api.example.com/v1', query: false));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(', or query.');

        UrlSetting::web(self::KEY, 'https://api.example.com/v1?tenant=a', query: false);
    }

    /**
     * `UrlSetting` is a utility container, not to be instantiated.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(UrlSetting::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(UrlSetting::class, $instance);
    }
}
