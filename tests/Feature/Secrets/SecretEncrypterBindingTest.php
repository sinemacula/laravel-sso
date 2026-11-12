<?php

declare(strict_types = 1);

namespace Tests\Feature\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Secrets\LaravelSecretEncrypter;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\TestCase;

/**
 * Feature tests for the secret encrypter's binding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LaravelSecretEncrypter::class)]
#[CoversClass(SsoServiceProvider::class)]
final class SecretEncrypterBindingTest extends TestCase
{
    /**
     * The default is Laravel's encrypter.
     *
     * @return void
     */
    public function testResolvesToLaravelsEncrypter(): void
    {
        self::assertInstanceOf(LaravelSecretEncrypter::class, $this->app?->make(SecretEncrypter::class));
    }

    /**
     * The default is shared within a scope and built afresh after it.
     *
     * @return void
     */
    public function testIsScoped(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $first = $app->make(SecretEncrypter::class);

        self::assertSame($first, $app->make(SecretEncrypter::class));

        $app->forgetScopedInstances();

        self::assertNotSame($first, $app->make(SecretEncrypter::class));
    }

    /**
     * A binding made before the provider registers is kept.
     *
     * @return void
     */
    public function testABindingMadeBeforeIsKept(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $own = new class implements SecretEncrypter {
            /**
             * The secret, unchanged.
             *
             * @param  string  $secret
             * @return string
             */
            #[\Override]
            public function encrypt(#[\SensitiveParameter] string $secret): string
            {
                return $secret;
            }

            /**
             * The ciphertext, unchanged.
             *
             * @param  string  $ciphertext
             * @return string
             */
            #[\Override]
            public function decrypt(string $ciphertext): string
            {
                return $ciphertext;
            }
        };

        $app->offsetUnset(SecretEncrypter::class);
        $app->singleton(SecretEncrypter::class, static fn (): SecretEncrypter => $own);

        // Testbench registered the provider already; register it again.
        (new SsoServiceProvider($app))->register();

        self::assertSame($own, $app->make(SecretEncrypter::class));

        $app->forgetScopedInstances();

        self::assertSame($own, $app->make(SecretEncrypter::class));
    }
}
