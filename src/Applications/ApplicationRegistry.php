<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications;

use Illuminate\Contracts\Config\Repository;

/**
 * The applications in `sso.applications`, read from the configuration on each
 * call.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApplicationRegistry
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the applications are read from. */
        private Repository $config,
    ) {}

    /**
     * The application under exactly the name, never read as a dotted path.
     *
     * @param  string  $name
     * @return ?\SineMacula\Laravel\Sso\Applications\Application
     *
     * @throws \InvalidArgumentException
     */
    public function find(string $name): ?Application
    {
        $applications = $this->applications();

        if (!Application::isName($name) || !array_key_exists($name, $applications)) {
            return null;
        }

        return Application::fromSettings($this->config, $name, $applications[$name]);
    }

    /**
     * Every registered application, by name, in the order configured.
     *
     * @return array<string, \SineMacula\Laravel\Sso\Applications\Application>
     *
     * @throws \InvalidArgumentException
     */
    public function all(): array
    {
        $all = [];

        foreach ($this->applications() as $name => $settings) {
            $all[(string) $name] = Application::fromSettings($this->config, (string) $name, $settings);
        }

        return $all;
    }

    /**
     * The configured block, once it is an array.
     *
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function applications(): array
    {
        $applications = $this->config->get('sso.applications', []);

        if (!is_array($applications)) {
            throw new \InvalidArgumentException('`sso.applications` must be an array of applications, by name.');
        }

        return $applications;
    }
}
