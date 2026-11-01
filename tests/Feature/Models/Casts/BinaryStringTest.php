<?php

declare(strict_types = 1);

namespace Tests\Feature\Models\Casts;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Models\Casts\BinaryString;
use SineMacula\Laravel\Sso\Models\Link;
use Tests\TestCase;

/**
 * Feature tests for the binary column cast: bytes read as they are, a stream
 * read from its start to its end, bytes bound as a string except on PostgreSQL,
 * where they are bound as a stream, and anything else refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BinaryString::class)]
final class BinaryStringTest extends TestCase
{
    /**
     * A string or `null` reads as it is; a stream reads from its start, even
     * once read.
     *
     * @return void
     */
    public function testReadsBytes(): void
    {
        $cast = new BinaryString;
        $link = new Link;

        self::assertNull($cast->get($link, 'subject', null, []));
        self::assertSame("a\x00b", $cast->get($link, 'subject', "a\x00b", []));

        $stream = fopen('php://memory', 'r+b');

        self::assertIsResource($stream);

        fwrite($stream, "\xffbytes");

        self::assertSame("\xffbytes", $cast->get($link, 'subject', $stream, []));
        self::assertSame("\xffbytes", $cast->get($link, 'subject', $stream, []));

        $this->expectExceptionObject(new \UnexpectedValueException('The [subject] column holds no bytes.'));

        $cast->get($link, 'subject', 12, []);
    }

    /**
     * Bytes are bound as a string on every engine but PostgreSQL, where they
     * are bound as a stream holding them, rewound, without connecting; `null`
     * stays `null`.
     *
     * @return void
     */
    public function testBindsBytesAsTheEngineNeeds(): void
    {
        $cast = new BinaryString;

        config()->set('database.connections.binary_sqlite', ['driver' => 'sqlite', 'database' => ':memory:']);

        $link = (new Link)->setConnection('binary_sqlite');

        self::assertNull($cast->set($link, 'subject', null, []));
        self::assertSame("a\x00b", $cast->set($link, 'subject', "a\x00b", []));

        config()->set('database.connections.binary_pgsql', ['driver' => 'pgsql', 'host' => '127.0.0.1', 'database' => 'sso', 'username' => 'sso', 'password' => '']);

        $postgres = (new Link)->setConnection('binary_pgsql');

        $stream = $cast->set($postgres, 'subject', "a\\x00\xff", []);

        self::assertIsResource($stream);
        self::assertSame(0, ftell($stream));
        self::assertSame("a\\x00\xff", stream_get_contents($stream));

        $this->expectExceptionObject(new \InvalidArgumentException('The [subject] column holds a string of bytes.'));

        $cast->set($link, 'subject', 12, []);
    }
}
