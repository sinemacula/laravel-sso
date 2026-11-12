<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The days before its end of validity a key or certificate is warned of; 0 is
 * always one, for a key whose validity has ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExpiryThresholds
{
    /** @var int The seconds in a day of a threshold. */
    public const int SECONDS_PER_DAY = 86400;

    /** @var string Why a value names no thresholds. */
    private const string MALFORMED = 'sso.keys.expiry_thresholds must be a list of distinct integers from 0 to %d, including 0.';

    /**
     * Constructor.
     *
     * @param  list<int>  $ascending
     */
    private function __construct(

        /** The days of each threshold, most urgent first. */
        private array $ascending,
    ) {}

    /**
     * Parse a list of distinct days from 0 to 365, in any order, including 0.
     *
     * @param  mixed  $value
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function parse(mixed $value): self
    {
        $days = is_array($value) && array_is_list($value) ? array_map(static fn (mixed $day): ?int => self::day($day), $value) : [];

        if (!in_array(0, $days, true) || in_array(null, $days, true) || count($days) !== count(array_unique($days))) {
            throw new \InvalidArgumentException(sprintf(self::MALFORMED, KeySettings::MAX_EXPIRY_THRESHOLD));
        }

        $days = array_values(array_filter($days, is_int(...)));

        sort($days);

        return new self($days);
    }

    /**
     * The largest threshold, in days.
     *
     * @return int
     */
    public function largest(): int
    {
        return $this->ascending[count($this->ascending) - 1];
    }

    /**
     * The most urgent threshold a validity ending then has reached by now, or
     * `null`; one is reached when the end is at or before now plus its days.
     *
     * @param  \DateTimeInterface  $notAfter
     * @param  \DateTimeInterface  $now
     * @return ?int
     */
    public function reachedBy(\DateTimeInterface $notAfter, \DateTimeInterface $now): ?int
    {
        $remaining = $notAfter->getTimestamp() - $now->getTimestamp();

        foreach ($this->ascending as $days) {
            if ($remaining <= $days * self::SECONDS_PER_DAY) {
                return $days;
            }
        }

        return null;
    }

    /**
     * The day a value names, or `null` when it names none in range.
     *
     * @param  mixed  $value
     * @return ?int
     */
    private static function day(mixed $value): ?int
    {
        $day = IntegerSetting::parse($value);

        return $day !== null && $day >= 0 && $day <= KeySettings::MAX_EXPIRY_THRESHOLD ? $day : null;
    }
}
