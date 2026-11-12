<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Connections;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Protocols\Preset;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * Registers the application's `cas` driver and `acme` OIDC preset.
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
