<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;

/**
 * Reads each flow's limits from `sso.rate_limits.<flow>.<scope>`; a missing or
 * malformed limit fails closed, never falls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AttemptLimits
{
    /** @var string The configuration key of the limits. */
    public const string KEY = 'sso.rate_limits';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the limits are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The flow's limits, keyed by scope in the flow's order.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow  $flow
     * @return array<string, \SineMacula\Laravel\Sso\RateLimiting\AttemptLimit>
     *
     * @throws \InvalidArgumentException
     */
    public function for(AttemptFlow $flow): array
    {
        $limits = [];

        foreach ($flow->scopes() as $scope) {

            $key = sprintf('%s.%s.%s', self::KEY, $flow->value, $scope->value);

            $limits[$scope->value] = self::fromValue($key, $this->config->get($key));
        }

        return $limits;
    }

    /**
     * Fail on the first missing or malformed limit of any flow.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        foreach (AttemptFlow::cases() as $flow) {
            $this->for($flow);
        }
    }

    /**
     * Build a limit from exactly a `max` and a `decay_seconds` within range.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptLimit
     *
     * @throws \InvalidArgumentException
     */
    private static function fromValue(string $key, mixed $value): AttemptLimit
    {
        $max   = is_array($value) && count($value) === 2 ? IntegerSetting::parse($value['max'] ?? null) : null;
        $decay = is_array($value) ? IntegerSetting::parse($value['decay_seconds'] ?? null) : null;

        if (!self::isWithin($max, AttemptLimit::MAX_ATTEMPTS) || !self::isWithin($decay, AttemptLimit::MAX_DECAY_SECONDS)) {
            throw new \InvalidArgumentException(self::message($key));
        }

        return new AttemptLimit($max, $decay);
    }

    /**
     * Whether a parsed setting is present and between 1 and its maximum.
     *
     * @param  ?int  $value
     * @param  int  $maximum
     * @return bool
     *
     * @phpstan-assert-if-true int $value
     */
    private static function isWithin(?int $value, int $maximum): bool
    {
        return $value !== null && $value >= 1 && $value <= $maximum;
    }

    /**
     * The message for a limit that is missing or malformed.
     *
     * @param  string  $key
     * @return string
     */
    private static function message(string $key): string
    {
        $message = '`%s` must be an array of `max` (1 to %d) and `decay_seconds` (1 to %d).';

        return sprintf($message, $key, AttemptLimit::MAX_ATTEMPTS, AttemptLimit::MAX_DECAY_SECONDS);
    }
}
