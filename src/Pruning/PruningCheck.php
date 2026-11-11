<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[pruning]`: the settings of the clean-up, while the package is in use
 * (SSO-11.11), each read as `PruneSettings` reads it, so the check and the
 * clean-up judge it the same way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PruningCheck implements ConfigurationCheck
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
     * Pruning is checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * The retention, the batch and the work cap.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $settings = new PruneSettings($this->config);

        return [$settings->retentionSeconds(...), $settings->batchSize(...), $settings->maxRowsPerKind(...)];
    }
}
