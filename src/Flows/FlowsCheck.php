<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[flows]`: checks the flows' own settings, read as `FlowSettings` reads them.
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
        return Features::isInUse($this->config);
    }

    /**
     * The request lifetime and the discovery minimum duration.
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
