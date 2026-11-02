<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

/**
 * What the SAML adapter holds a response to, for one connection (SSO-2.6,
 * SSO-6.2, SSO-6.7, SSO-6.8): the identity provider certificates the connection
 * trusts (PEM), the only keys a signature is verified with, since a key the
 * message carries is never trusted; the signature, key transport and data
 * encryption algorithms the connection allows; and what yields the service
 * provider's decryption keys (PEM private keys), called only when the response
 * carries an encrypted assertion, so a response that carries none never
 * decrypts a stored key.
 *
 * The decryption keys are held in a `\SensitiveParameterValue`; a dump shows
 * how many certificates and algorithms it holds, never a key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ResponsePolicy
{
    /** @var \SensitiveParameterValue What yields the decryption keys, a `\Closure(): list<\SineMacula\Laravel\Sso\Secrets\Secret>`. */
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

        /** The trusted identity provider certificates, as PEM. */
        public array $trustedCertificates,

        /** The signature algorithms allowed. */
        public array $signatureAlgorithms,

        /** The key transport algorithms allowed. */
        public array $keyTransportAlgorithms = [],

        /** The data encryption algorithms allowed. */
        public array $dataEncryptionAlgorithms = [],

        // Yields the service provider's decryption keys; held wrapped
        ?\Closure $decryptionKeys = null,
    ) {
        $this->decryptionKeys = new \SensitiveParameterValue($decryptionKeys ?? static fn (): array => []);
    }

    /**
     * What a dump shows: how many certificates and algorithms it holds, never a
     * key.
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
     * Refuse to be serialised: it may yield private keys.
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
     * The service provider's decryption keys, as PEM private keys, decrypted
     * now for the decryption that asks.
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
