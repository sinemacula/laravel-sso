<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;

/**
 * The limits on each flow (SSO-11.8), from `sso.rate_limits.<flow>.<scope>`,
 * one for each scope the flow is counted in.
 *
 * Every limit is always on. Each is exactly `['max' => int, 'decay_seconds' =>
 * int]`, each an integer or the canonical decimal string `env()` returns for
 * one, `max` from 1 to 1000000 and `decay_seconds` from 1 to 86400. A limit
 * that is missing, `null` or malformed fails closed with an
 * `InvalidArgumentException` naming its key: nothing falls back to a literal,
 * and nothing turns a limit off. The configuration is read on every call, so
 * nothing is kept from one request to the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AttemptLimits
{
    /** @var string The key, in the configuration, of the limits. */
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
     * The limits on the flow, keyed by scope, in the order of the flow's
     * scopes.
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
     * Check the limits on every flow, failing on the first that is missing or
     * malformed.
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
     * Build a limit from its configured value: exactly a `max` and a
     * `decay_seconds`, each an integer within its range.
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

        if ($max === null || $decay === null || $max < 1 || $max > AttemptLimit::MAX_ATTEMPTS || $decay < 1 || $decay > AttemptLimit::MAX_DECAY_SECONDS) {
            throw new \InvalidArgumentException(self::message($key));
        }

        return new AttemptLimit($max, $decay);
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
