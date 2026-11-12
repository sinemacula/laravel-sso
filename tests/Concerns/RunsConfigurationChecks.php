<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Sso\Config\ConfigurationChecker;

/**
 * Runs one configuration check through the checker, as `sso:check` does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RunsConfigurationChecks
{
    /**
     * The check's problems: `null` when it does not apply, `[]` for none.
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
     * Configure a valid baseline, so a test changes only what it checks.
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
