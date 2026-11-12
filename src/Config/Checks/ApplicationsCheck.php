<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config\Checks;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * Checks each application in `sso.applications` the way the flows read it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApplicationsCheck implements ConfigurationCheck
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
     * Applies while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * The block's shape, then each application.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $applications = $this->config->get('sso.applications', []);

        if (!is_array($applications)) {
            return [
                static function (): void {
                    throw new \InvalidArgumentException('`sso.applications` must be an array of applications, by name.');
                },
            ];
        }

        $checks = [];

        foreach ($applications as $name => $settings) {
            $checks[] = fn (): Application => Application::fromSettings($this->config, (string) $name, $settings);
        }

        return $checks;
    }
}
