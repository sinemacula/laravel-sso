<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * A key pair `Keys\KeyGenerator` has just generated, with its self-signed
 * certificate (SSO-2.7), on its way to being encrypted and stored.
 *
 * The private key is held only as a `Secrets\Secret`, so it leaves the object
 * only through `reveal()`, for the encrypter. A dump shows every field but the
 * private key, which it shows as `[redacted]`, and the object refuses to be
 * serialised or unserialised, so the key cannot reach a log, a queue, a cache
 * or an event (SSO-2.5).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GeneratedKey
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $privateKey
     * @param  string  $publicKey
     * @param  string  $certificate
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  int  $bits
     * @param  \Carbon\CarbonImmutable  $notBefore
     * @param  \Carbon\CarbonImmutable  $notAfter
     * @param  string  $fingerprint
     */
    public function __construct(

        /** The private key, PEM-encoded (PKCS #8), unencrypted. */
        public Secret $privateKey,

        /** The public key, PEM-encoded. */
        public string $publicKey,

        /** The self-signed certificate, PEM-encoded. */
        public string $certificate,

        /** The kind of key. */
        public KeyType $type,

        /** The RSA modulus, or the elliptic curve's size (256 for P-256), in bits. */
        public int $bits,

        /** When the certificate's validity starts, in UTC. */
        public CarbonImmutable $notBefore,

        /** When the certificate's validity ends, in UTC. */
        public CarbonImmutable $notAfter,

        /** The lower-case hex SHA-256 fingerprint of the certificate's DER. */
        public string $fingerprint,
    ) {}

    /**
     * What a dump shows: every field but the private key.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'privateKey'  => '[redacted]',
            'publicKey'   => $this->publicKey,
            'certificate' => $this->certificate,
            'type'        => $this->type->value,
            'bits'        => $this->bits,
            'notBefore'   => $this->notBefore->format('Y-m-d\TH:i:s\Z'),
            'notAfter'    => $this->notAfter->format('Y-m-d\TH:i:s\Z'),
            'fingerprint' => $this->fingerprint,
        ];
    }

    /**
     * Refuse to be serialised: a generated key lives only until it is encrypted
     * and stored.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A generated key cannot be serialised.');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A generated key cannot be unserialised.');
    }
}
