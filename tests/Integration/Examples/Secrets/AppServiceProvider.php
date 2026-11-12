<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Secrets;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;

/**
 * Binds the KMS secret encrypter in place of the default under `APP_KEY`.
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
