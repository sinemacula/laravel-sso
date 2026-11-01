<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications;

use Illuminate\Contracts\Config\Repository;

/**
 * The applications registered in `sso.applications` (SSO-5.5, decision D7),
 * read from the configuration on each call, so nothing of one request is kept
 * for the next (SSO-11.2).
 *
 * An application is found only under exactly its name: a name that is not an
 * application's name, or that names none, is answered with `null`, never with
 * another application, and a key is never read as a path (`web.x` is no
 * application, not `web`'s `x`). A registered application whose settings are
 * malformed fails closed with the `InvalidArgumentException` of
 * `Application::fromSettings()`; the boot check reports it first.
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
     * The application registered under exactly the name, or `null` when none
     * is.
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

        return Application::fromSettings($name, $applications[$name]);
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
            $all[(string) $name] = Application::fromSettings((string) $name, $settings);
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
