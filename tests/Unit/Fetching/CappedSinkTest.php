<?php

declare(strict_types = 1);

namespace Tests\Unit\Fetching;

use GuzzleHttp\Psr7\NoSeekStream;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Fetching\CappedSink;

/**
 * Unit tests for the size-capped sink a hop's body is written into.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CappedSink::class)]
final class CappedSinkTest extends TestCase
{
    /**
     * The write that would pass the cap, and every write after, takes nothing
     * and answers `0`.
     *
     * @return void
     */
    public function testTakesUpToTheCapAndRefusesTheRest(): void
    {
        $sink   = new CappedSink(10);
        $stream = $sink->stream();

        self::assertSame(6, $stream->write('abcdef'));
        self::assertSame(4, $stream->write('ghij'));
        self::assertSame(0, $stream->write(''));
        self::assertFalse($sink->exceeded());

        self::assertSame(0, $stream->write('k'));
        self::assertTrue($sink->exceeded());
        self::assertSame(0, $stream->write(''));
        self::assertSame('abcdefghij', (string) $stream);
        self::assertSame(10, $stream->getSize());
    }

    /**
     * A single write over the cap takes nothing.
     *
     * @return void
     */
    public function testRefusesAWriteOverTheCapWhole(): void
    {
        $sink = new CappedSink(4);

        self::assertSame(0, $sink->stream()->write('abcde'));
        self::assertTrue($sink->exceeded());
        self::assertSame('', (string) $sink->stream());
    }

    /**
     * Its stream reads back as any stream does, from wherever its pointer is.
     *
     * @return void
     */
    public function testReadsBackAsAStream(): void
    {
        $stream = (new CappedSink(64))->stream();

        $stream->write('hello world');

        self::assertSame(11, $stream->tell());
        self::assertTrue($stream->isSeekable());

        $stream->rewind();

        self::assertSame('hello', $stream->read(5));
        self::assertSame(' world', $stream->getContents());
        self::assertTrue($stream->eof());
    }

    /**
     * A body is read from its start, no further than a byte past the cap, or
     * from where it is if unseekable.
     *
     * @return void
     */
    public function testReadsABodyNoFurtherThanABytePastTheCap(): void
    {
        $body = Utils::streamFor(str_repeat('a', 2000));

        $body->read(100);

        self::assertSame(str_repeat('a', 1025), CappedSink::read($body, 1024));
        self::assertSame(str_repeat('a', 2000), CappedSink::read($body, 4096));

        $unseekable = Utils::streamFor(Utils::tryFopen('php://memory', 'w+'));

        $unseekable->write('abcdef');
        $unseekable->seek(2);

        $stream = new NoSeekStream($unseekable);

        self::assertSame('cde', CappedSink::read($stream, 2));
    }
}
