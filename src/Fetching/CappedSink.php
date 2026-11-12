<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use GuzzleHttp\Psr7\FnStream;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;

/**
 * The size-capped sink for one hop's response body. A write past the cap
 * returns `0`, so cURL aborts the transfer whatever the Guzzle version.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CappedSink
{
    /** @var \Psr\Http\Message\StreamInterface The stream the bytes within the cap are written to. */
    private readonly StreamInterface $buffer;

    /** @var \Psr\Http\Message\StreamInterface The stream Guzzle writes the body to. */
    private readonly StreamInterface $stream;

    /** @var int The bytes written so far. */
    private int $written = 0;

    /** @var bool Whether a write was refused for passing the cap. */
    private bool $exceeded = false;

    /**
     * Constructor.
     *
     * @param  int  $cap
     *
     * @throws \RuntimeException
     */
    public function __construct(

        /** The most bytes the body may hold. */
        private readonly int $cap,
    ) {
        $this->buffer = Utils::streamFor(Utils::tryFopen('php://temp', 'w+'));
        $this->stream = FnStream::decorate($this->buffer, ['write' => $this->write(...)]);
    }

    /**
     * Read the body from its start, at most one byte past the cap.
     *
     * @param  \Psr\Http\Message\StreamInterface  $body
     * @param  int  $cap
     * @return string
     *
     * @throws \RuntimeException
     */
    public static function read(StreamInterface $body, int $cap): string
    {
        if ($body->isSeekable()) {
            $body->rewind();
        }

        return Utils::copyToString($body, $cap + 1);
    }

    /**
     * The stream to give Guzzle as the hop's `sink`.
     *
     * @return \Psr\Http\Message\StreamInterface
     */
    public function stream(): StreamInterface
    {
        return $this->stream;
    }

    /**
     * Whether the body passed the cap.
     *
     * @return bool
     */
    public function exceeded(): bool
    {
        return $this->exceeded;
    }

    /**
     * Write the bytes within the cap; past it, write nothing from then on and
     * return `0`.
     *
     * @param  string  $bytes
     * @return int
     *
     * @throws \RuntimeException
     */
    private function write(string $bytes): int
    {
        if ($this->exceeded || $this->written + strlen($bytes) > $this->cap) {
            $this->exceeded = true;

            return 0;
        }

        $written = $this->buffer->write($bytes);

        $this->written += $written;

        return $written;
    }
}
