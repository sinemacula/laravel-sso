<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice;

/**
 * The counts of one run of `Keys\ExpiryReport`; the keys go to the caller as
 * read, so a run's memory does not grow with them.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExpiryRun implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  int  $listed
     * @param  int  $expired
     * @param  array<string, int>  $notices
     */
    public function __construct(

        /** How many keys and certificates are expiring or have expired. */
        public int $listed = 0,

        /** How many of them have expired. */
        public int $expired = 0,

        /** How many keys, listed or not, ended with each notice, by its value. */
        public array $notices = [],
    ) {}

    /**
     * This run with one more entry listed.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\ExpiringKey  $entry
     * @return self
     */
    public function listing(ExpiringKey $entry): self
    {
        return new self($this->listed + 1, $this->expired + ($entry->expired ? 1 : 0), $this->notices);
    }

    /**
     * This run with one more key that ended with the notice.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice  $notice
     * @return self
     */
    public function noting(ExpiryNotice $notice): self
    {
        return new self($this->listed, $this->expired, [$notice->value => $this->count($notice) + 1] + $this->notices);
    }

    /**
     * How many keys ended with the notice.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice  $notice
     * @return int
     */
    public function count(ExpiryNotice $notice): int
    {
        return $this->notices[$notice->value] ?? 0;
    }

    /**
     * Whether a dispatch threw, leaving a warning for a later run.
     *
     * @return bool
     */
    public function hasFailures(): bool
    {
        return $this->count(ExpiryNotice::FAILED) > 0;
    }

    /**
     * What `json_encode()` writes, with a count for every notice.
     *
     * @return array{listed: int, expired: int, notices: array<string, int>}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        $notices = [];

        foreach (ExpiryNotice::cases() as $notice) {
            $notices[$notice->value] = $this->count($notice);
        }

        return ['listed' => $this->listed, 'expired' => $this->expired, 'notices' => $notices];
    }
}
