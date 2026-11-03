<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Logging;

use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Logging\SanitizingLogger;

/**
 * The example application's secret encrypter (SSO-2.5, SSO-11.9): the package's
 * secrets kept by the application's key management service, and each refusal of
 * the service logged through the package's own logger, so the line is sanitised
 * and redacted as the package's are, and lands on its channel.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KmsSecretEncrypter implements SecretEncrypter
{
    /**
     * Constructor.
     *
     * @param  \Tests\Integration\Examples\Logging\KmsClient  $kms
     * @param  \SineMacula\Laravel\Sso\Logging\SanitizingLogger  $logger
     */
    public function __construct(

        /** The key management service's client. */
        private KmsClient $kms,

        /** The package's logger. */
        private SanitizingLogger $logger,
    ) {}

    /**
     * The secret, encrypted by the key management service; a refusal is logged
     * through the package's logger and thrown as a `RuntimeException`.
     *
     * @param  string  $secret
     * @return string
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function encrypt(#[\SensitiveParameter] string $secret): string
    {
        try {
            return $this->kms->encrypt($secret);
        } catch (KmsException $exception) {
            $this->logger->error('KMS encrypt failed.', ['exception' => $exception]);

            throw new \RuntimeException('The secret could not be encrypted.', 0, $exception);
        }
    }

    // @snippet-start logging-adapter-decrypt
    /**
     * The secret the key management service decrypts from the ciphertext; a
     * refusal is logged through the package's logger and thrown as a
     * `RuntimeException`, which the package treats as a server error.
     *
     * @param  string  $ciphertext
     * @return string
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function decrypt(string $ciphertext): string
    {
        try {
            return $this->kms->decrypt($ciphertext);
        } catch (KmsException $exception) {
            $this->logger->error('KMS decrypt failed.', ['exception' => $exception]);

            throw new \RuntimeException('The secret could not be decrypted.', 0, $exception);
        }
    }
    // @snippet-end logging-adapter-decrypt
}
