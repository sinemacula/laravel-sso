<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Logging;

/**
 * A stand-in KMS client whose refusals name the API key, as SDK errors do.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KmsClient
{
    /** @var int The code the service refuses a call with. */
    public const int ACCESS_DENIED = 403;

    /** @var array<string, string> Each secret kept, by its ciphertext. */
    private array $secrets = [];

    /** @var bool Whether the client's access to the key is revoked. */
    private bool $revoked = false;

    /**
     * Constructor.
     *
     * @param  string  $keyId
     * @param  string  $apiKey
     */
    public function __construct(

        /** The key the service encrypts under. */
        private readonly string $keyId,

        /** The API key every call carries. */
        #[\SensitiveParameter]
        private readonly string $apiKey,
    ) {}

    /**
     * The ciphertext the service issues for the secret.
     *
     * @param  string  $secret
     * @return string
     *
     * @throws \Tests\Integration\Examples\Logging\KmsException
     */
    public function encrypt(#[\SensitiveParameter] string $secret): string
    {
        $this->authorize('Encrypt');

        $ciphertext = sprintf('%s:%08d', $this->keyId, count($this->secrets) + 1);

        $this->secrets[$ciphertext] = $secret;

        return $ciphertext;
    }

    /**
     * The secret the service keeps for the ciphertext.
     *
     * @param  string  $ciphertext
     * @return string
     *
     * @throws \Tests\Integration\Examples\Logging\KmsException
     */
    public function decrypt(string $ciphertext): string
    {
        $this->authorize('Decrypt');

        return $this->secrets[$ciphertext] ?? throw new KmsException("Decrypt on {$this->keyId} found no such ciphertext.");
    }

    /**
     * How many secrets the service keeps.
     *
     * @return int
     */
    public function kept(): int
    {
        return count($this->secrets);
    }

    /**
     * Revoke the client's access to the key, so every later call is refused.
     *
     * @return void
     */
    public function revoke(): void
    {
        $this->revoked = true;
    }

    /**
     * Refuse the operation once the client's access is revoked.
     *
     * @param  string  $operation
     * @return void
     *
     * @throws \Tests\Integration\Examples\Logging\KmsException
     */
    private function authorize(string $operation): void
    {
        if ($this->revoked) {
            throw new KmsException("{$operation} on {$this->keyId} was refused for x-api-key={$this->apiKey}", self::ACCESS_DENIED);
        }
    }
}
