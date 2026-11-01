<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Sso\Config\ConfigurationChecker;

/**
 * Runs one configuration check through the checker, as the boot check and
 * `sso:check` run it, against the test application's configuration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RunsConfigurationChecks
{
    /**
     * What the check found: `null` when it does not apply, otherwise its
     * problems, `[]` for none.
     *
     * @param  class-string<\SineMacula\Laravel\Sso\Contracts\ConfigurationCheck>  $check
     * @return ?list<string>
     */
    protected function problemsOf(string $check): ?array
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return (new ConfigurationChecker($app, ['subject' => $check]))->report()['subject'];
    }

    /**
     * Turn the package on with a protocol, the base URL its endpoints are built
     * from and one valid application, so a test changes only what it checks.
     *
     * @return void
     */
    protected function useThePackage(): void
    {
        config()->set('sso.features.saml2', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');
        config()->set('sso.applications', [
            'web' => ['redirect_uri' => 'https://app.example.com/auth/sso/complete', 'external_sign_in' => true],
        ]);
    }
}
