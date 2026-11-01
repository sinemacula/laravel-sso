<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[flows]`: the settings of the flows themselves, while the package is in use
 * (SSO-5.1, SSO-3.5), each read as `FlowSettings` reads it, so the check and
 * the flows judge it the same way. The tables' names are checked under
 * `[storage]`, and each application's handoff lifetime under `[applications]`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FlowsCheck implements ConfigurationCheck
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration checked. */
        private Repository $config,
    ) {}

    /**
     * The flows are checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * The authorisation request's lifetime and the least time a discovery start
     * takes.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $settings = new FlowSettings($this->config);

        return [
            static fn (): int => $settings->requestTtlSeconds(),
            static fn (): int => $settings->discoveryMinimumDurationMilliseconds(),
        ];
    }
}
