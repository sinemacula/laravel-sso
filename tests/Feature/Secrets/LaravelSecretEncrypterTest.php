<?php

declare(strict_types = 1);

namespace Tests\Feature\Secrets;

use Illuminate\Contracts\Encryption\StringEncrypter;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Secrets\LaravelSecretEncrypter;
use Tests\TestCase;

/**
 * Feature tests for the default secret encrypter: a secret round-trips through
 * Laravel's encrypter under `app.key`, its ciphertext shows nothing of it, and
 * a tampered ciphertext is a server error that shows nothing of it either.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LaravelSecretEncrypter::class)]
final class LaravelSecretEncrypterTest extends TestCase
{
    /** @var string A secret no output may show. */
    private const string SECRET = 'the-client-secret-value';

    /**
     * A secret decrypts to itself.
     *
     * @return void
     */
    public function testRoundTrips(): void
    {
        $encrypter = $this->encrypter();

        self::assertSame(self::SECRET, $encrypter->decrypt($encrypter->encrypt(self::SECRET)));
    }

    /**
     * The ciphertext shows nothing of the secret, and two encryptions of one
     * secret differ.
     *
     * @return void
     */
    public function testTheCiphertextShowsNothingOfTheSecret(): void
    {
        $encrypter = $this->encrypter();
        $first     = $encrypter->encrypt(self::SECRET);
        $second    = $encrypter->encrypt(self::SECRET);

        self::assertNotSame(self::SECRET, $first);
        self::assertStringNotContainsString(self::SECRET, $first);
        self::assertStringNotContainsString(self::SECRET, (string) base64_decode($first, true));
        self::assertNotSame($first, $second);
    }

    /**
     * It is Laravel's encrypter under `app.key`: Laravel's own decrypts what it
     * encrypts.
     *
     * @return void
     */
    public function testUsesLaravelsEncrypter(): void
    {
        /** @var \Illuminate\Contracts\Encryption\StringEncrypter $laravel */
        $laravel = $this->app?->make(StringEncrypter::class);

        self::assertSame(self::SECRET, $laravel->decryptString($this->encrypter()->encrypt(self::SECRET)));
        self::assertSame(self::SECRET, $this->encrypter()->decrypt($laravel->encryptString(self::SECRET)));
    }

    /**
     * A tampered ciphertext throws a `RuntimeException` whose message and trace
     * show nothing of the secret.
     *
     * @return void
     */
    public function testATamperedCiphertextIsAServerErrorThatShowsNothing(): void
    {
        $encrypter = $this->encrypter();
        $payload   = json_decode((string) base64_decode($encrypter->encrypt(self::SECRET), true), true);

        self::assertIsArray($payload);
        self::assertIsString($payload['value']);

        $payload['value'] = strrev($payload['value']);
        $tampered         = base64_encode((string) json_encode($payload));

        try {
            $encrypter->decrypt($tampered);

            self::fail('Expected the tampered ciphertext to be refused.');
        } catch (\RuntimeException $exception) {
            self::assertStringNotContainsString(self::SECRET, $exception->getMessage());
            self::assertStringNotContainsString(self::SECRET, $exception->getTraceAsString());
            self::assertStringNotContainsString(self::SECRET, print_r($exception->getTrace(), true));
            self::assertStringNotContainsString(self::SECRET, (string) $exception);
        }
    }

    /**
     * Anything that is not a ciphertext throws a `RuntimeException` too.
     *
     * @return void
     */
    public function testANonCiphertextIsAServerError(): void
    {
        $this->expectException(\RuntimeException::class);

        $this->encrypter()->decrypt(self::SECRET);
    }

    /**
     * The encrypter, built on Laravel's.
     *
     * @return \SineMacula\Laravel\Sso\Secrets\LaravelSecretEncrypter
     */
    private function encrypter(): LaravelSecretEncrypter
    {
        /** @var \Illuminate\Contracts\Encryption\StringEncrypter $laravel */
        $laravel = $this->app?->make(StringEncrypter::class);

        return new LaravelSecretEncrypter($laravel);
    }
}
