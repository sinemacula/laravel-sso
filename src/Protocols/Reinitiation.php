<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How a driver judged an unsolicited response (SSO-5.8, SSO-6.11): allowed,
 * with the connection's start URL naming the connection, which the browser is
 * sent to so the application starts an SP-initiated flow, and the record that
 * keeps the response from being used again; or refused with a reason.
 *
 * An allowed one never signs anyone in: the completion records it against
 * replay, under the connection's lock and with the connection checked again,
 * and answers `reinitiated`; the unsolicited identity never carries into the
 * new flow.
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

        /** The connection's start URL, naming the connection, for an allowed one. */
        public ?string $startUrl,

        /** What keeps the response from being used again, for an allowed one. */
        public ?ReplayRecord $replay,

        /** Why it was refused, for a refused one. */
        public ?FailureReason $reason,
    ) {}

    /**
     * The response passed the unsolicited profile: send the browser to the
     * start URL, once the record is made.
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
