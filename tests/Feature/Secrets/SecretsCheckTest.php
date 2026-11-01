<?php

declare(strict_types = 1);

namespace Tests\Feature\Secrets;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Secrets\LaravelSecretEncrypter;
use SineMacula\Laravel\Sso\Secrets\SecretsCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for `[secrets]`: checked while the package is in use; the
 * default encrypter must round-trip under `app.key`; an application's own
 * encrypter must resolve and is never called.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SecretsCheck::class)]
final class SecretsCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /** @var string The problem of a default encrypter that cannot work. */
    private const string UNUSABLE = 'The default secret encrypter cannot encrypt and decrypt with `app.key`; set APP_KEY, or bind your own SecretEncrypter.';

    /**
     * Not checked while the package is not in use, even with no `app.key`.
     *
     * @return void
     */
    public function testDoesNotApplyWhileThePackageIsNotInUse(): void
    {
        $this->withAppKey('');

        self::assertNull($this->problemsOf(SecretsCheck::class));
    }

    /**
     * The default encrypter, under the test application's key, passes.
     *
     * @return void
     */
    public function testTheDefaultPassesWithAnAppKey(): void
    {
        $this->useThePackage();

        self::assertSame([], $this->problemsOf(SecretsCheck::class));
    }

    /**
     * With no `app.key`, the problem names APP_KEY and no key.
     *
     * @return void
     */
    public function testTheDefaultFailsWithoutAnAppKey(): void
    {
        $this->useThePackage();
        $this->withAppKey('');

        self::assertSame([self::UNUSABLE], $this->problemsOf(SecretsCheck::class));
    }

    /**
     * A default encrypter whose round trip gives back something else, or
     * throws, fails.
     *
     * @return void
     */
    public function testTheDefaultFailsWhenItsRoundTripFails(): void
    {
        $this->useThePackage();

        foreach ([self::stringEncrypter(false), self::stringEncrypter(true)] as $broken) {
            $this->app?->instance(SecretEncrypter::class, new LaravelSecretEncrypter($broken));

            self::assertSame([self::UNUSABLE], $this->problemsOf(SecretsCheck::class));
        }
    }

    /**
     * An application's own encrypter that resolves passes without being called,
     * even with no `app.key` for the default.
     *
     * @return void
     */
    public function testAnApplicationsOwnEncrypterIsOnlyResolved(): void
    {
        $this->useThePackage();
        $this->withAppKey('');

        $this->app?->instance(SecretEncrypter::class, new class implements SecretEncrypter {
            /**
             * Never called by the check.
             *
             * @param  string  $secret
             * @return string
             *
             * @throws \LogicException
             */
            #[\Override]
            public function encrypt(#[\SensitiveParameter] string $secret): string
            {
                throw new \LogicException('The check called encrypt().');
            }

            /**
             * Never called by the check.
             *
             * @param  string  $ciphertext
             * @return string
             *
             * @throws \LogicException
             */
            #[\Override]
            public function decrypt(string $ciphertext): string
            {
                throw new \LogicException('The check called decrypt().');
            }
        });

        self::assertSame([], $this->problemsOf(SecretsCheck::class));
    }

    /**
     * An application's own encrypter that cannot be resolved fails with the
     * container's message.
     *
     * @return void
     */
    public function testAnApplicationsOwnEncrypterThatCannotResolveFails(): void
    {
        $this->useThePackage();

        $this->app?->bind(SecretEncrypter::class, static function (): SecretEncrypter {
            throw new \RuntimeException('The key management service is not configured.');
        });

        self::assertSame(['The key management service is not configured.'], $this->problemsOf(SecretsCheck::class));
    }

    /**
     * Set `app.key` and forget Laravel's encrypter and the scoped instances, so
     * the next resolution reads it.
     *
     * @param  string  $key
     * @return void
     */
    private function withAppKey(string $key): void
    {
        config()->set('app.key', $key);

        $this->app?->forgetInstance('encrypter');
        $this->app?->forgetScopedInstances();
    }

    /**
     * Laravel's string encrypter, broken: its decryption throws, or gives back
     * something other than what was encrypted.
     *
     * @param  bool  $throws
     * @return \Illuminate\Contracts\Encryption\StringEncrypter
     */
    private static function stringEncrypter(bool $throws): StringEncrypter
    {
        $encrypter = self::createStub(StringEncrypter::class);

        $encrypter->method('encryptString')->willReturn('not-the-probe');

        if ($throws) {
            $encrypter->method('decryptString')->willThrowException(new DecryptException('The payload is invalid.'));
        } else {
            $encrypter->method('decryptString')->willReturnArgument(0);
        }

        return $encrypter;
    }
}
