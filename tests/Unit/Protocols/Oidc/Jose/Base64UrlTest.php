<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\Jose;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Base64Url;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for strict unpadded base64url.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Base64Url::class)]
final class Base64UrlTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /**
     * Bytes encode without padding in the URL-safe alphabet, and decode back.
     *
     * @return void
     */
    public function testBytesRoundTrip(): void
    {
        self::assertSame('', Base64Url::encode(''));
        self::assertSame('-_8', Base64Url::encode("\xfb\xff"));
        self::assertSame('YQ', Base64Url::encode('a'));
        self::assertSame('YWI', Base64Url::encode('ab'));
        self::assertSame("\xfb\xff", Base64Url::decode('-_8'));
        self::assertSame('a', Base64Url::decode('YQ'));
        self::assertSame('', Base64Url::decode(''));
    }

    /**
     * Rows of `[value]`: values that are not canonical unpadded base64url.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusals(): iterable
    {
        yield from [
            'padding'            => ['YQ=='],
            'the plus sign'      => ['+_8'],
            'the slash'          => ['-/8'],
            'whitespace'         => ['Y Q'],
            'a newline'          => ["YQ\n"],
            'one character'      => ['Y'],
            'five characters'    => ['YWJjZ'],
            'non-canonical bits' => ['YR'],
            'a dot'              => ['YQ.'],
        ];
    }

    /**
     * Anything but the canonical encoding is refused.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testAnythingButTheCanonicalEncodingIsRefused(string $value): void
    {
        self::assertNull(Base64Url::decode($value));
    }
}
