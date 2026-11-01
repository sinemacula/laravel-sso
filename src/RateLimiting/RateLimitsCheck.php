<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope;

/**
 * `[rate_limits]`: the limits on each flow, while the package is in use
 * (SSO-11.8). Each flow's limits are read as the limiter reads them (see
 * `AttemptLimits::for()`), so the check and the limiter judge them the same
 * way: one problem for each flow whose limits are missing or malformed.
 *
 * A limit the package does not count (a scope its flow is not counted in, such
 * as a `per_connection` under `redemption`, or a flow it does not have) would
 * seem to limit something and limit nothing, so it is a problem too. The table
 * and the connection are checked under `[storage]`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RateLimitsCheck implements ConfigurationCheck
{
    /** @var list<string> Keys of the `sso.rate_limits` block besides its flows. */
    private const array STORAGE_KEYS = ['table', 'connection'];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptLimits  $limits
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The limits on each flow, read as the limiter reads them. */
        private AttemptLimits $limits,

        /** Configuration the limits block is read from. */
        private Repository $config,
    ) {}

    /**
     * The limits are checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * Each flow's limits, then the limits the package does not count.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $checks = [];

        foreach (AttemptFlow::cases() as $flow) {
            $checks[] = fn (): array => $this->limits->for($flow);
        }

        $checks[] = $this->assertOnlyCountedLimits(...);

        return $checks;
    }

    /**
     * Refuse a key of the limits block the package does not count: a flow it
     * does not have, or a scope its flow is not counted in.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertOnlyCountedLimits(): void
    {
        $block     = $this->config->get(AttemptLimits::KEY);
        $uncounted = is_array($block) ? self::uncounted($block) : [];

        if ($uncounted !== []) {
            throw new \InvalidArgumentException(self::message($uncounted));
        }
    }

    /**
     * The keys of the limits block the package does not count, in order: each
     * name that is neither a flow nor a storage key, and each scope under a
     * flow that the flow is not counted in.
     *
     * @param  array<array-key, mixed>  $block
     * @return list<string>
     */
    private static function uncounted(array $block): array
    {
        $uncounted = [];

        foreach ($block as $name => $limits) {

            $flow = AttemptFlow::tryFrom((string) $name);

            $keys = $flow === null
                ? self::unknownName((string) $name)
                : self::uncountedScopes($flow, $limits);

            $uncounted = [...$uncounted, ...$keys];
        }

        return $uncounted;
    }

    /**
     * The name of the limits block's key when it is not a flow, unless it is
     * one of the storage keys.
     *
     * @param  string  $name
     * @return list<string>
     */
    private static function unknownName(string $name): array
    {
        return in_array($name, self::STORAGE_KEYS, true) ? [] : [$name];
    }

    /**
     * The scopes under the flow's key that the flow is not counted in, each as
     * `<flow>.<scope>`.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow  $flow
     * @param  mixed  $limits
     * @return list<string>
     */
    private static function uncountedScopes(AttemptFlow $flow, mixed $limits): array
    {
        if (!is_array($limits)) {
            return [];
        }

        $counted   = self::scopesOf($flow);
        $uncounted = [];

        foreach (array_keys($limits) as $scope) {

            if (in_array((string) $scope, $counted, true)) {
                continue;
            }

            $uncounted[] = "{$flow->value}.{$scope}";
        }

        return $uncounted;
    }

    /**
     * The names of the scopes the flow is counted in.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow  $flow
     * @return list<string>
     */
    private static function scopesOf(AttemptFlow $flow): array
    {
        return array_map(static fn (AttemptScope $scope): string => $scope->value, $flow->scopes());
    }

    /**
     * The message naming the keys the package does not count.
     *
     * @param  non-empty-list<string>  $uncounted
     * @return string
     */
    private static function message(array $uncounted): string
    {
        $keys = implode(', ', array_map(static fn (string $key): string => '`' . AttemptLimits::KEY . ".{$key}`", $uncounted));

        return count($uncounted) === 1
            ? "Remove {$keys}: the package counts no such limit, so it limits nothing."
            : "Remove {$keys}: the package counts no such limits, so they limit nothing.";
    }
}
