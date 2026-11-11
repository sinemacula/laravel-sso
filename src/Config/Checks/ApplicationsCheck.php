<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config\Checks;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[applications]`: the applications in `sso.applications`, while the package
 * is in use, each named by a lower-case key.
 *
 * Each application is judged by `Applications\Application::fromSettings()`, the
 * one way the flows judge it too: exactly one redirect URI, compared later as
 * an exact string (see `UrlSetting::redirect()`); whether it allows sign-in
 * through an external provider (off unless set); whether the handoff code is
 * delivered in the fragment (the default) or the query; whether it offers
 * discovery and the fallback URL a miss leads to (required while discovery is
 * on for it and the `discovery` feature is on); whether it accepts unlinked
 * handoffs (off unless set); and the handoff code's lifetime (1 to 300 seconds,
 * 60 by default). Any other key is refused, so a misspelt setting is never
 * silently left at its default.
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
     * The applications are checked while the package is in use.
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
