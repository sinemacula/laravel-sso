<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Oidc;

/**
 * An RSA or EC signing key of the fake OpenID provider. RSA generation takes
 * tens of milliseconds, so a test class may share one key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FakeSigningKey
{
    /** @var array<string, string> OpenSSL's name of each curve, by its JWK name. */
    public const array CURVES = ['P-256' => 'prime256v1', 'P-384' => 'secp384r1', 'P-521' => 'secp521r1'];

    /** @var array<string, string> The private RSA members of a JWK, by OpenSSL's name of each. */
    private const array RSA_PRIVATE = ['d' => 'd', 'p' => 'p', 'q' => 'q', 'dmp1' => 'dp', 'dmq1' => 'dq', 'iqmp' => 'qi'];

    /** @var string The key's type: `RSA` or `EC`. */
    public string $type;

    /** @var ?string The curve of an elliptic curve key. */
    public ?string $curve;

    /** @var int The modulus's or the curve's size, in bits. */
    public int $bits;

    /** @var string The PEM public key. */
    public string $publicKeyPem;

    /** @var array<string, mixed> What OpenSSL reads from the private key. */
    private array $details;

    /**
     * Constructor.
     *
     * @param  string  $privateKeyPem
     * @param  ?string  $kid
     *
     * @throws \LogicException
     */
    public function __construct(

        /** The PEM private key, which may be one the package must refuse. */
        #[\SensitiveParameter]
        public string $privateKeyPem,

        /** The key's `kid`, or `null` for a key published without one. */
        public ?string $kid,
    ) {
        $key     = openssl_pkey_get_private($privateKeyPem);
        $details = $key === false ? null : openssl_pkey_get_details($key);

        if (!is_array($details)) {
            throw new \LogicException('The fake OpenID provider could not read its key.');
        }

        $this->details      = $details;
        $this->type         = isset($details['ec']) ? 'EC' : 'RSA';
        $this->curve        = $this->type === 'EC' ? array_flip(self::CURVES)[$details['ec']['curve_name']] : null;
        $this->bits         = (int) $details['bits'];
        $this->publicKeyPem = (string) $details['key'];
    }

    /**
     * Generate an RSA key.
     *
     * @param  ?string  $kid
     * @param  int  $bits
     * @return self
     *
     * @throws \LogicException
     */
    public static function rsa(?string $kid = 'rsa-1', int $bits = 2048): self
    {
        return new self(self::generated(['private_key_bits' => $bits]), $kid);
    }

    /**
     * Generate an EC key.
     *
     * @param  ?string  $kid
     * @param  string  $curve
     * @return self
     *
     * @throws \LogicException
     */
    public static function ec(?string $kid = 'ec-1', string $curve = 'P-256'): self
    {
        return new self(self::generated(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => self::CURVES[$curve]]), $kid);
    }

    /**
     * The same key under another `kid`, or none.
     *
     * @param  ?string  $kid
     * @return self
     *
     * @throws \LogicException
     */
    public function withKid(?string $kid): self
    {
        return new self($this->privateKeyPem, $kid);
    }

    /**
     * The public JWK as published; a `null` `alg` or `use` is left out and the
     * extra members are laid over it.
     *
     * @param  ?string  $alg
     * @param  ?string  $use
     * @param  array<string, mixed>  $extra
     * @return array<string, mixed>
     */
    public function jwk(?string $alg = null, ?string $use = 'sig', array $extra = []): array
    {
        $jwk = $this->type === 'RSA'
            ? ['kty' => 'RSA', 'n' => self::encoded($this->details['rsa']['n']), 'e' => self::encoded($this->details['rsa']['e'])]
            : ['kty' => 'EC', 'crv' => $this->curve, 'x' => $this->coordinate('x'), 'y' => $this->coordinate('y')];

        $described = array_filter(['kid' => $this->kid, 'use' => $use, 'alg' => $alg], static fn (?string $value): bool => $value !== null);

        return [...$jwk, ...$described, ...$extra];
    }

    /**
     * The JWK with its private members, for a JWKS that wrongly publishes them.
     *
     * @param  ?string  $alg
     * @return array<string, mixed>
     */
    public function privateJwk(?string $alg = null): array
    {
        if ($this->type === 'EC') {
            return [...$this->jwk($alg), 'd' => $this->coordinate('d')];
        }

        $private = [];

        foreach (self::RSA_PRIVATE as $from => $to) {
            $private[$to] = self::encoded($this->details['rsa'][$from]);
        }

        return [...$this->jwk($alg), ...$private];
    }

    /**
     * A self-signed certificate of the key as base64 DER, for `x5c`.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function certificate(): string
    {
        $key         = openssl_pkey_get_private($this->privateKeyPem);
        $request     = $key === false ? false : openssl_csr_new(['commonName' => 'fake-signing-key.example.test'], $key, ['digest_alg' => 'sha256']);
        $certificate = $request instanceof \OpenSSLCertificateSigningRequest ? openssl_csr_sign($request, null, $this->privateKeyPem, 1, ['digest_alg' => 'sha256']) : false;

        if ($certificate === false || !openssl_x509_export($certificate, $pem)) {
            throw new \LogicException('The fake OpenID provider could not certify its key.');
        }

        return (string) preg_replace('/-----[^-]+-----|\s+/', '', $pem);
    }

    /**
     * An EC coordinate or private scalar, padded to the curve's length.
     *
     * @param  string  $name
     * @return string
     */
    private function coordinate(string $name): string
    {
        $bytes = intdiv($this->bits + 7, 8);
        $value = $this->details['ec'][$name] ?? '';

        return self::encoded(str_pad(is_string($value) ? $value : '', $bytes, "\x00", STR_PAD_LEFT));
    }

    /**
     * Generate a PEM private key with OpenSSL.
     *
     * @param  array<string, mixed>  $options
     * @return string
     *
     * @throws \LogicException
     */
    private static function generated(array $options): string
    {
        $key = openssl_pkey_new($options);

        if ($key === false || !openssl_pkey_export($key, $pem)) {
            throw new \LogicException('The fake OpenID provider could not generate its key.');
        }

        return $pem;
    }

    /**
     * Encode the bytes as unpadded base64url.
     *
     * @param  mixed  $bytes
     * @return string
     */
    private static function encoded(#[\SensitiveParameter] mixed $bytes): string
    {
        return rtrim(strtr(base64_encode(is_string($bytes) ? $bytes : ''), '+/', '-_'), '=');
    }
}
