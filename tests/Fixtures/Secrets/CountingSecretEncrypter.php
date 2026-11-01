<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets;

use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;

/**
 * A secret encrypter for the package's own tests that passes each call to the
 * encrypter it wraps and counts the decryptions, so a test can show that a
 * secret is decrypted only when, and as often as, it is asked for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountingSecretEncrypter implements SecretEncrypter
{
    /** @var int How many ciphertexts it was asked to decrypt. */
    public int $decryptions = 0;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SecretEncrypter  $inner
     */
    public function __construct(

        /** The encrypter each call is passed to. */
        private readonly SecretEncrypter $inner,
    ) {}

    /**
     * The secret, encrypted by the wrapped encrypter.
     *
     * @param  string  $secret
     * @return string
     */
    #[\Override]
    public function encrypt(#[\SensitiveParameter] string $secret): string
    {
        return $this->inner->encrypt($secret);
    }

    /**
     * Count the decryption, and answer the secret the wrapped encrypter
     * decrypts.
     *
     * @param  string  $ciphertext
     * @return string
     */
    #[\Override]
    public function decrypt(string $ciphertext): string
    {
        $this->decryptions++;

        return $this->inner->decrypt($ciphertext);
    }
}
