<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Secrets;

/**
 * The public half of a stored key pair or certificate; never a private key.
 *
 * A PEM must be exactly one block of the expected type, so OpenSSL never reads
 * a `file://` path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MaskedKey implements \JsonSerializable
{
    /** @var string The marker of a PEM block that holds a private key. */
    private const string PRIVATE_KEY = 'PRIVATE KEY';

    /** @var string The opening of any PEM block. */
    private const string PEM_BEGIN = '-----BEGIN ';

    /** @var string The refusal of a malformed certificate. */
    private const string MALFORMED_CERTIFICATE = 'The certificate is not one PEM-encoded X.509 certificate.';

    /** @var string The refusal of a malformed public key. */
    private const string MALFORMED_PUBLIC_KEY = 'The public key is not one PEM-encoded public key.';

    /**
     * Constructor.
     *
     * @param  bool  $isSet
     * @param  ?string  $certificate
     * @param  ?string  $publicKey
     * @param  ?string  $fingerprint
     */
    private function __construct(

        /** Whether a key or certificate is stored. */
        public bool $isSet,

        /** The certificate, PEM-encoded, when there is one. */
        public ?string $certificate,

        /** The public key, PEM-encoded, when one is set. */
        public ?string $publicKey,

        /** The lower-case hex SHA-256 of the certificate's DER, else the public key's. */
        public ?string $fingerprint,
    ) {}

    /**
     * The certificate, its public key and its fingerprint, in canonical PEM.
     *
     * @param  string  $pem
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromCertificate(string $pem): self
    {
        self::refuseAPrivateKey($pem);

        $pem = trim($pem);

        if (!self::isOneBlock($pem, 'CERTIFICATE')) {
            throw new \InvalidArgumentException(self::MALFORMED_CERTIFICATE);
        }

        $certificate = self::quietly(static fn (): false|\OpenSSLCertificate => openssl_x509_read($pem));
        $canonical   = '';

        if ($certificate === false || !openssl_x509_export($certificate, $canonical)) {
            throw new \InvalidArgumentException(self::MALFORMED_CERTIFICATE);
        }

        $fingerprint = openssl_x509_fingerprint($certificate, 'sha256');
        $publicKey   = self::publicKeyOf($certificate);

        if ($fingerprint === false || $publicKey === null) {
            throw new \InvalidArgumentException('The certificate\'s public key cannot be read.');
        }

        return new self(true, $canonical, $publicKey, $fingerprint);
    }

    /**
     * The public key and its fingerprint, with no certificate.
     *
     * @param  string  $pem
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromPublicKey(string $pem): self
    {
        self::refuseAPrivateKey($pem);

        $pem = trim($pem);

        if (!self::isOneBlock($pem, 'PUBLIC KEY') && !self::isOneBlock($pem, 'RSA PUBLIC KEY')) {
            throw new \InvalidArgumentException(self::MALFORMED_PUBLIC_KEY);
        }

        $canonical = self::publicKeyOf($pem);
        $der       = $canonical === null ? false : self::der($canonical);

        if ($canonical === null || $der === false) {
            throw new \InvalidArgumentException(self::MALFORMED_PUBLIC_KEY);
        }

        return new self(true, null, $canonical, hash('sha256', $der));
    }

    /**
     * No key or certificate is stored.
     *
     * @return self
     */
    public static function unset(): self
    {
        return new self(false, null, null, null);
    }

    /**
     * The fields with snake_case keys.
     *
     * @return array<string, bool|string|null>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'set'         => $this->isSet,
            'certificate' => $this->certificate,
            'public_key'  => $this->publicKey,
            'fingerprint' => $this->fingerprint,
        ];
    }

    /**
     * Refuse a PEM that holds a private key.
     *
     * @param  string  $pem
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function refuseAPrivateKey(string $pem): void
    {
        if (str_contains($pem, self::PRIVATE_KEY)) {
            throw new \InvalidArgumentException('A masked key never holds a private key; give the certificate or the public key.');
        }
    }

    /**
     * Whether the trimmed PEM is exactly one block of the given type.
     *
     * @param  string  $pem
     * @param  string  $type
     * @return bool
     */
    private static function isOneBlock(string $pem, string $type): bool
    {
        return str_starts_with($pem, self::PEM_BEGIN . $type . '-----')
            && str_ends_with($pem, '-----END ' . $type . '-----')
            && substr_count($pem, self::PEM_BEGIN) === 1;
    }

    /**
     * The canonical public key PEM, or `null` when OpenSSL cannot read one.
     *
     * @param  \OpenSSLCertificate|string  $source
     * @return ?string
     */
    private static function publicKeyOf(\OpenSSLCertificate|string $source): ?string
    {
        $key     = self::quietly(static fn (): false|\OpenSSLAsymmetricKey => openssl_pkey_get_public($source));
        $details = $key     === false ? false : openssl_pkey_get_details($key);
        $pem     = $details === false ? null : ($details['key'] ?? null);

        return is_string($pem) ? $pem : null;
    }

    /**
     * The DER a single-block PEM encodes.
     *
     * @param  string  $pem
     * @return false|string
     */
    private static function der(string $pem): false|string
    {
        $body = preg_replace('/-----(?:BEGIN|END) [A-Z ]+-----|\s+/', '', $pem);

        return is_string($body) && $body !== '' ? base64_decode($body, true) : false;
    }

    /**
     * Run an OpenSSL read with its warning silenced and its error queue
     * cleared, so neither reaches a log or a later call.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $read
     * @return TResult
     */
    private static function quietly(\Closure $read): mixed
    {
        set_error_handler(static fn (): bool => true);

        try {
            return $read();
        } finally {
            restore_error_handler();

            do {
                $error = openssl_error_string();
            } while ($error !== false);
        }
    }
}
