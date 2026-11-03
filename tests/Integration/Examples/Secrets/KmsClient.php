<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Secrets;

use Random\RandomException;

/**
 * The example application's client of its key management service (SSO-2.5),
 * standing in for the service itself: it holds each named key's versions of
 * material, encrypts under a key's current version with AES-256-GCM, decrypts
 * under whichever version encrypted, so a rotation of its own keys never stops
 * it decrypting what it encrypted, and refuses with a `RuntimeException` what
 * no version of its keys decrypts. It counts the requests it is sent, as the
 * service's audit log would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KmsClient
{
    /** @var string The cipher the service encrypts with. */
    private const string CIPHER = 'aes-256-gcm';

    /** @var int The length of an initialisation vector, in bytes. */
    private const int IV_LENGTH = 12;

    /** @var int The length of an authentication tag, in bytes. */
    private const int TAG_LENGTH = 16;

    /** @var array<string, list<string>> Each key's versions of material, by its name, the last the current one. */
    private array $keys = [];

    /** @var int How many requests the service has been sent. */
    private int $requests = 0;

    /**
     * Create the named keys, each with its first version of material.
     *
     * @param  string  ...$keyNames
     *
     * @throws \Random\RandomException
     */
    public function __construct(string ...$keyNames)
    {
        foreach ($keyNames as $keyName) {
            $this->keys[$keyName] = [random_bytes(32)];
        }
    }

    /**
     * The plaintext, encrypted under the current version of the named key: the
     * key's name, the version and the sealed value, joined by colons.
     *
     * @param  string  $keyName
     * @param  string  $plaintext
     * @return string
     *
     * @throws \RuntimeException
     */
    public function encrypt(string $keyName, #[\SensitiveParameter] string $plaintext): string
    {
        $this->requests++;

        $versions = $this->keys[$keyName] ?? [];
        $version  = count($versions) - 1;
        $material = $versions[$version] ?? throw new \RuntimeException("The key management service has no key [{$keyName}].");
        $iv       = self::iv();
        $tag      = '';
        $sealed   = openssl_encrypt($plaintext, self::CIPHER, $material, OPENSSL_RAW_DATA, $iv, $tag, '', self::TAG_LENGTH);

        if ($sealed === false) {
            throw new \RuntimeException('The key management service could not encrypt.');
        }

        return implode(':', [$keyName, $version, base64_encode($iv . $tag . $sealed)]);
    }

    /**
     * The plaintext the ciphertext holds, decrypted under the version of the
     * key that encrypted it.
     *
     * @param  string  $ciphertext
     * @return string
     *
     * @throws \RuntimeException
     */
    public function decrypt(string $ciphertext): string
    {
        $this->requests++;

        [$keyName, $version, $sealed] = explode(':', $ciphertext, 3) + ['', '', ''];

        $material  = $this->keys[$keyName][(int) $version] ?? null;
        $plaintext = $material === null ? false : self::open($material, base64_decode($sealed, true));

        if ($plaintext === false) {
            throw new \RuntimeException('The key management service cannot decrypt the ciphertext.');
        }

        return $plaintext;
    }

    /**
     * Add a new version of the named key's material, which encrypts from now
     * on; every earlier version still decrypts what it encrypted.
     *
     * @param  string  $keyName
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function rotate(string $keyName): void
    {
        $this->keys[$keyName][] = random_bytes(32);
    }

    /**
     * How many requests the service has been sent.
     *
     * @return int
     */
    public function requests(): int
    {
        return $this->requests;
    }

    /**
     * A fresh initialisation vector.
     *
     * @return string
     *
     * @throws \RuntimeException
     */
    private static function iv(): string
    {
        try {
            return random_bytes(self::IV_LENGTH);
        } catch (RandomException $exception) {
            throw new \RuntimeException('The key management service could not encrypt.', 0, $exception);
        }
    }

    /**
     * The plaintext the sealed value holds under the material, or `false` when
     * it is not one the material sealed.
     *
     * @param  string  $material
     * @param  false|string  $sealed
     * @return false|string
     */
    private static function open(#[\SensitiveParameter] string $material, false|string $sealed): false|string
    {
        if ($sealed === false || strlen($sealed) < self::IV_LENGTH + self::TAG_LENGTH) {
            return false;
        }

        $iv  = substr($sealed, 0, self::IV_LENGTH);
        $tag = substr($sealed, self::IV_LENGTH, self::TAG_LENGTH);

        return openssl_decrypt(substr($sealed, self::IV_LENGTH + self::TAG_LENGTH), self::CIPHER, $material, OPENSSL_RAW_DATA, $iv, $tag);
    }
}
