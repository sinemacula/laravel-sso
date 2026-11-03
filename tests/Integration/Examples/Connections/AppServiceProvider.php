<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Connections;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Protocols\Preset;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * The example application's service provider (SSO-2.2): once the protocol
 * registry resolves, it registers the application's own `cas` driver and its
 * own `acme` preset for OIDC. It registers after the package's provider, as an
 * application's providers do; whether the registry has resolved by then or
 * resolves later, each registration runs once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Register the application's protocol and preset.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start register-protocol
        $this->callAfterResolving(ProtocolManager::class, function (ProtocolManager $protocols): void {
            $protocols->extend('cas', fn () => new CasDriver);
        });
        // @snippet-end register-protocol
        // @snippet-start register-preset
        $this->callAfterResolving(ProtocolManager::class, function (ProtocolManager $protocols): void {
            $protocols->registerPreset(new Preset('acme', 'oidc', [
                'scopes'              => ['openid', 'email', 'profile'],
                'id_token_algorithms' => ['ES256'],
            ], ['email' => 'email']));
        });
        // @snippet-end register-preset
    }
}
