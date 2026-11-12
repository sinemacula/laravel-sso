<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * A driver's verdict on an unsolicited response: send the browser to start a
 * fresh flow, or refuse. An allowed one never signs anyone in.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Reinitiation
{
    /**
     * Constructor.
     *
     * @param  ?string  $startUrl
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ReplayRecord  $replay
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The connection's start URL, for an allowed one. */
        public ?string $startUrl,

        /** What keeps the response from being used again, for an allowed one. */
        public ?ReplayRecord $replay,

        /** Why it was refused, for a refused one. */
        public ?FailureReason $reason,
    ) {}

    /**
     * The response passed the unsolicited profile; send the browser to the
     * start URL once the replay record is made.
     *
     * @param  string  $startUrl
     * @param  \SineMacula\Laravel\Sso\Protocols\ReplayRecord  $replay
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function allowed(string $startUrl, ReplayRecord $replay): self
    {
        $scheme = parse_url($startUrl, PHP_URL_SCHEME);

        if (!is_string($scheme) || strtolower($scheme) !== 'https') {
            throw new \InvalidArgumentException('A re-initiation leads to an absolute https URL.');
        }

        return new self($startUrl, $replay, null);
    }

    /**
     * The response was refused, for the reason given.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self(null, null, $reason);
    }

    /**
     * Whether the response may be re-initiated.
     *
     * @return bool
     */
    public function isAllowed(): bool
    {
        return $this->startUrl !== null;
    }
}
