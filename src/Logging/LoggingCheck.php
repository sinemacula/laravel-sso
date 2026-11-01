<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[logging]`: where the package logs and what it keeps, while the package is
 * in use (SSO-5.7, SSO-9.8, SSO-11.9). The channel must be the default one or a
 * channel `logging.channels` configures; the diagnostic length an integer from
 * 64 to 4096; and the added redacted keys a list of key names, each holding a
 * letter or a digit. Each is read as `LoggingSettings` reads it for the logger,
 * so the check and the logger judge a setting the same way, and each is its own
 * check, so one run reports every problem.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LoggingCheck implements ConfigurationCheck
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Logging\LoggingSettings  $settings
     */
    public function __construct(

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
        return Features::isInUse();
    }

    /**
     * The channel, the diagnostic length and the redacted keys: together, what
     * `LoggingSettings::validate()` checks.
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
