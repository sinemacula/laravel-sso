<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use GuzzleHttp\Psr7\FnStream;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;

/**
 * Where one hop's response body is written as it arrives, never past the size
 * cap (SSO-2.9), and how a body is read back within it.
 *
 * Its stream refuses a write that would take the body past the cap: it writes
 * nothing and answers `0`, so cURL aborts the transfer with a write error there
 * and then, on every supported Guzzle, whatever Guzzle makes of the progress
 * callback's answer. A body sent without a length, or with a false one, is
 * never held past the cap.
 *
 * It is made for one hop, and holds the body in a `php://temp` stream, which
 * Guzzle hands back as the response's body.
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
     * The body read from its start, no further than a byte past the cap, so a
     * body that is too large is never read into memory whole.
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
     * Whether a write was refused for passing the cap: the body is too large.
     *
     * @return bool
     */
    public function exceeded(): bool
    {
        return $this->exceeded;
    }

    /**
     * Write the bytes when the body stays within the cap; otherwise write
     * nothing, answer `0` and remember the body is too large, as every later
     * write then is.
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
