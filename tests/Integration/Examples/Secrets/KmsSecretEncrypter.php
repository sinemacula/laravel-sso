<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Secrets;

use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;

/**
 * A secret encrypter that keeps secrets under the KMS key `sso-secrets`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KmsSecretEncrypter implements SecretEncrypter
{
    /**
     * Take the client of the key management service.
     *
     * @param  \Tests\Integration\Examples\Secrets\KmsClient  $kms
     */
    public function __construct(

        /** The KMS the secrets are kept under. */
        private KmsClient $kms,
    ) {}

    // @snippet-start kms-secret-encrypter
    /**
     * The secret, encrypted under the service's key.
     *
     * @param  string  $secret
     * @return string
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function encrypt(#[\SensitiveParameter] string $secret): string
    {
        return $this->kms->encrypt('sso-secrets', $secret);
    }

    /**
     * The secret the ciphertext holds, decrypted by the service under the
     * version of its key that encrypted it.
     *
     * @param  string  $ciphertext
     * @return string
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function decrypt(string $ciphertext): string
    {
        return $this->kms->decrypt($ciphertext);
    }
    // @snippet-end kms-secret-encrypter
}
