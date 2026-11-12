<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

/**
 * Encrypts the client secrets and private keys the package keeps at rest.
 *
 * Never log the plaintext or put it in an exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SecretEncrypter
{
    /**
     * Encrypt the secret for storage.
     *
     * @param  string  $secret
     * @return string
     *
     * @throws \RuntimeException
     */
    public function encrypt(#[\SensitiveParameter] string $secret): string;

    /**
     * Decrypt the stored ciphertext; one no key decrypts is a server error.
     *
     * @param  string  $ciphertext
     * @return string
     *
     * @throws \RuntimeException
     */
    public function decrypt(string $ciphertext): string;
}
