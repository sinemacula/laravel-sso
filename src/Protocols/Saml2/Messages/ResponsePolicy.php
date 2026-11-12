<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

/**
 * A connection's trusted certificates and allowed algorithms for reading a
 * response. Decryption keys load lazily, only for an encrypted assertion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ResponsePolicy
{
    /** @var \SensitiveParameterValue A `\Closure(): list<\SineMacula\Laravel\Sso\Secrets\Secret>` of decryption keys. */
    private \SensitiveParameterValue $decryptionKeys;

    /**
     * Constructor.
     *
     * @param  list<string>  $trustedCertificates
     * @param  list<string>  $signatureAlgorithms
     * @param  list<string>  $keyTransportAlgorithms
     * @param  list<string>  $dataEncryptionAlgorithms
     * @param  ?\Closure(): list<\SineMacula\Laravel\Sso\Secrets\Secret>  $decryptionKeys
     */
    public function __construct(

        /** The trusted IdP certificates, as PEM; the only verification keys. */
        public array $trustedCertificates,

        /** The signature algorithms allowed. */
        public array $signatureAlgorithms,

        /** The key transport algorithms allowed. */
        public array $keyTransportAlgorithms = [],

        /** The data encryption algorithms allowed. */
        public array $dataEncryptionAlgorithms = [],

        // Held wrapped, so not promoted
        ?\Closure $decryptionKeys = null,
    ) {
        $this->decryptionKeys = new \SensitiveParameterValue($decryptionKeys ?? static fn (): array => []);
    }

    /**
     * Show only counts, never a key.
     *
     * @return array<string, int>
     */
    public function __debugInfo(): array
    {
        return [
            'trusted_certificates'       => count($this->trustedCertificates),
            'signature_algorithms'       => count($this->signatureAlgorithms),
            'key_transport_algorithms'   => count($this->keyTransportAlgorithms),
            'data_encryption_algorithms' => count($this->dataEncryptionAlgorithms),
        ];
    }

    /**
     * Refuse to be serialised; it may yield private keys.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A response policy cannot be serialised.');
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
        throw new \LogicException('A response policy cannot be unserialised.');
    }

    /**
     * The SP decryption keys as PEM, decrypted on each call.
     *
     * @return list<\SineMacula\Laravel\Sso\Secrets\Secret>
     */
    public function decryptionKeys(): array
    {
        /** @var \Closure(): list<\SineMacula\Laravel\Sso\Secrets\Secret> $keys */
        $keys = $this->decryptionKeys->getValue();

        return $keys();
    }
}
