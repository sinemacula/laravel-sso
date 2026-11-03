<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice;

/**
 * One key or certificate a run of `Keys\ExpiryReport` lists: what it is,
 * whether its validity has ended by the run's instant, the most urgent
 * threshold it has reached, and what the run did about warning of it.
 * Everything currently expiring or expired is listed, whatever was notified
 * before.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExpiringKey implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeySummary  $key
     * @param  bool  $expired
     * @param  ?int  $thresholdDays
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice  $notice
     */
    public function __construct(

        /** The key or certificate. */
        public KeySummary $key,

        /** Whether its validity has ended. */
        public bool $expired,

        /** The most urgent threshold reached, in days; none when it has reached none. */
        public ?int $thresholdDays,

        /** What the run did about warning of it. */
        public ExpiryNotice $notice,
    ) {}

    /**
     * What `json_encode()` writes, with snake_case keys and times in UTC.
     *
     * @return array{key_id: string, connection_id: string, use: string, not_after: ?string, expired: bool, threshold_days: ?int, notice: string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'key_id'         => $this->key->id,
            'connection_id'  => $this->key->connectionId,
            'use'            => $this->key->use->value,
            'not_after'      => $this->key->notAfter?->utc()->format('Y-m-d\TH:i:s\Z'),
            'expired'        => $this->expired,
            'threshold_days' => $this->thresholdDays,
            'notice'         => $this->notice->value,
        ];
    }
}
