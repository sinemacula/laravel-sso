<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[logging]`: checks each logging setting as the logger reads it, separately
 * so one run reports every problem.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LoggingCheck implements ConfigurationCheck
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Sso\Logging\LoggingSettings  $settings
     */
    public function __construct(

        /** The configuration that says whether the package is in use. */
        private Repository $config,

        /** The settings checked. */
        private LoggingSettings $settings,
    ) {}

    /**
     * Logging is checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * What `LoggingSettings::validate()` checks, one closure per setting.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [
            function (): void {
                $this->settings->assertChannelConfigured();
            },
            fn (): int => $this->settings->maxDiagnosticLength(),
            fn (): array => $this->settings->redactedKeys(),
        ];
    }
}
