<?php

declare(strict_types = 1);

namespace Tests\Integration\Secrets;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Secrets\LaravelSecretEncrypter;
use Tests\TestCase;

/**
 * Integration tests, on a real database, of rotating `app.key` (SSO-2.5): a
 * secret stored encrypted under the old key still decrypts once the key is
 * rotated, while the old key is listed in `app.previous_keys`, with no
 * migration of what is stored; once it is no longer listed, decryption is a
 * server error.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LaravelSecretEncrypter::class)]
final class KeyRotationTest extends TestCase
{
    /** @var string The table the ciphertext is stored in for the test. */
    private const string TABLE = 'secret_rotation_examples';

    /** @var string The key the secret is first encrypted under. */
    private const string KEY_A = 'base64:QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=';

    /** @var string The key it is rotated to. */
    private const string KEY_B = 'base64:QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=';

    /** @var string A secret no output may show. */
    private const string SECRET = 'the-client-secret-value';

    /**
     * A secret stored under the old key decrypts after rotation while the old
     * key is a previous one, and not once it is dropped.
     *
     * @return void
     */
    public function testAStoredSecretSurvivesRotationWhileTheOldKeyIsPrevious(): void
    {
        Schema::dropIfExists(self::TABLE);
        Schema::create(self::TABLE, static function (Blueprint $table): void {
            $table->id();
            $table->text('ciphertext');
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::dropIfExists(self::TABLE);
        });

        $this->useKeys(self::KEY_A, []);

        DB::table(self::TABLE)->insert(['ciphertext' => $this->encrypter()->encrypt(self::SECRET)]);

        $stored = DB::table(self::TABLE)->value('ciphertext');

        self::assertIsString($stored);
        self::assertStringNotContainsString(self::SECRET, $stored);

        $this->useKeys(self::KEY_B, [self::KEY_A]);

        self::assertSame(self::SECRET, $this->encrypter()->decrypt($stored));
        self::assertSame(self::SECRET, $this->encrypter()->decrypt($this->encrypter()->encrypt(self::SECRET)));

        $this->useKeys(self::KEY_B, []);

        try {
            $this->encrypter()->decrypt($stored);

            self::fail('Expected a ciphertext under a key no longer listed to be refused.');
        } catch (\RuntimeException $exception) {
            self::assertStringNotContainsString(self::SECRET, $exception->getMessage());
        }
    }

    /**
     * A secret encrypted after rotation is under the new key: the old key alone
     * does not decrypt it.
     *
     * @return void
     */
    public function testANewSecretIsEncryptedUnderTheNewKey(): void
    {
        $this->useKeys(self::KEY_B, [self::KEY_A]);

        $ciphertext = $this->encrypter()->encrypt(self::SECRET);

        $this->useKeys(self::KEY_A, []);

        $this->expectException(\RuntimeException::class);

        $this->encrypter()->decrypt($ciphertext);
    }

    /**
     * Set the application key and its previous keys, and forget Laravel's
     * encrypter and the scoped instances, so the next resolution reads them.
     *
     * @param  string  $key
     * @param  list<string>  $previous
     * @return void
     */
    private function useKeys(string $key, array $previous): void
    {
        config()->set('app.key', $key);
        config()->set('app.previous_keys', $previous);

        $this->app?->forgetInstance('encrypter');
        $this->app?->forgetScopedInstances();
    }

    /**
     * The bound secret encrypter, the default.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SecretEncrypter
     */
    private function encrypter(): SecretEncrypter
    {
        /** @var \SineMacula\Laravel\Sso\Contracts\SecretEncrypter $encrypter */
        $encrypter = $this->app?->make(SecretEncrypter::class);

        self::assertInstanceOf(LaravelSecretEncrypter::class, $encrypter);

        return $encrypter;
    }
}
