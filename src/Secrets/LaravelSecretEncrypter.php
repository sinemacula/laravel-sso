<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Secrets;

use Illuminate\Contracts\Encryption\StringEncrypter;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;

/**
 * The default secret encrypter: Laravel's encrypter, keyed by `app.key`.
 *
 * Decryption also tries `app.previous_keys`, so rotating the key needs no
 * migration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LaravelSecretEncrypter implements SecretEncrypter
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Encryption\StringEncrypter  $encrypter
     */
    public function __construct(

        /** Laravel's encrypter, as its `encrypter` binding serves it. */
        private StringEncrypter $encrypter,
    ) {}

    /**
     * The secret, encrypted under `app.key`.
     *
     * @param  string  $secret
     * @return string
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function encrypt(#[\SensitiveParameter] string $secret): string
    {
        return $this->encrypter->encryptString($secret);
    }

    /**
     * The secret, decrypted under `app.key` or any of `app.previous_keys`.
     *
     * @param  string  $ciphertext
     * @return string
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function decrypt(string $ciphertext): string
    {
        return $this->encrypter->decryptString($ciphertext);
    }
}
