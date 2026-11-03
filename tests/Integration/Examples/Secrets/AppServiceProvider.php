<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Secrets;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;

/**
 * The example application's service provider (SSO-2.5): it binds the
 * application's own secret encrypter, keeping the package's secrets under its
 * key management service, in place of the default under `APP_KEY`. It registers
 * after the package's provider, as an application's providers do, so its
 * binding replaces the default as any later binding does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Bind the application's secret encrypter.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start kms-encrypter-binding
        // One encrypter per request or job: nothing of one is kept for the next
        $this->app->scoped(SecretEncrypter::class, KmsSecretEncrypter::class);
        // @snippet-end kms-encrypter-binding
    }
}
