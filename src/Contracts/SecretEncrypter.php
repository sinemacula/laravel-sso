<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

/**
 * Secret encrypter contract (SSO-2.5): encrypts the secrets the package keeps
 * at rest (client secrets and private keys) and decrypts them when a flow needs
 * them.
 *
 * The default is Laravel's encrypter, so the application key and its previous
 * keys (`app.previous_keys`) decrypt what each encrypted, and rotating the key
 * needs no migration. An application may bind a key management service instead.
 * An implementation never logs, reports or puts in an exception the plaintext
 * it is given or returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SecretEncrypter
{
    /**
     * The secret, encrypted for storage; a `RuntimeException` when it cannot
     * be.
     *
     * @param  string  $secret
     * @return string
     *
     * @throws \RuntimeException
     */
    public function encrypt(#[\SensitiveParameter] string $secret): string;

    /**
     * The secret the stored ciphertext holds. A ciphertext no current or
     * previous key decrypts is a server error, never a refusal.
     *
     * @param  string  $ciphertext
     * @return string
     *
     * @throws \RuntimeException
     */
    public function decrypt(string $ciphertext): string;
}
