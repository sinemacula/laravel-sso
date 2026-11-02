<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SimpleSAML\SAML2\XML\saml\EncryptedAssertion;
use SimpleSAML\XMLSecurity\Alg\Encryption\EncryptionAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\KeyTransportAlgorithmFactory;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\CryptoEncoding\PEM;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\SymmetricKey;
use SimpleSAML\XMLSecurity\XML\xenc\EncryptedKey;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy;

/**
 * Decrypts the one `EncryptedAssertion` of a SAML response into the bytes of
 * its assertion, with the library's own key transport and block decryption,
 * held to the connection's policy (SSO-6.7, SSO-6.8).
 *
 * The `EncryptionMethod` of the data must be one the connection allows and the
 * library decrypts correctly: AES-128-GCM or AES-192-GCM (AES-256-GCM is out
 * until `xml-security` 3, `docs/design/saml-library.md`), or AES-CBC only when
 * the connection lists it, and then only when the enclosing response carries a
 * signature from a trusted certificate that was verified before anything is
 * decrypted, so the decryption is never an oracle. Exactly one `EncryptedKey`
 * must carry the session key, by RSA-OAEP only, never RSA 1.5, and it is tried
 * against each of the service provider's decryption keys (current, then
 * retiring within their overlap) until one yields a key of the data algorithm's
 * length. The ciphertext and the plaintext are each capped.
 *
 * Every refusal and every failure, whether of policy, key, padding, tag or
 * length, is the one `ReadFailure` (`decryption_failed`, `decryption`), so
 * nothing distinguishes one from another. The plaintext is returned for the
 * hardened parser; nothing here parses it. It holds nothing between calls
 * (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AssertionDecryptor
{
    /** @var list<string> The key transport algorithms the package decrypts: RSA-OAEP only. */
    public const array KEY_TRANSPORT_ALGORITHMS = [C::KEY_TRANSPORT_OAEP, C::KEY_TRANSPORT_OAEP_MGF1P];

    /** @var array<string, int> The data encryption algorithms the package decrypts, with the length of their key in bytes. */
    public const array DATA_ENCRYPTION_ALGORITHMS = [
        C::BLOCK_ENC_AES128_GCM => 16,
        C::BLOCK_ENC_AES192_GCM => 24,
        C::BLOCK_ENC_AES128     => 16,
        C::BLOCK_ENC_AES192     => 24,
        C::BLOCK_ENC_AES256     => 32,
    ];

    /** @var list<string> The data encryption algorithms decrypted only after a verified response signature: AES-CBC. */
    public const array CBC_ALGORITHMS = [C::BLOCK_ENC_AES128, C::BLOCK_ENC_AES192, C::BLOCK_ENC_AES256];

    /** @var int The most a ciphertext may exceed the plaintext cap by, for its initialisation vector, tag and padding, in bytes. */
    private const int OVERHEAD_BYTES = 64;

    /**
     * The bytes of the assertion the element encrypts, once the policy admits
     * it and one of the service provider's keys decrypts it.
     *
     * @param  \SimpleSAML\SAML2\XML\saml\EncryptedAssertion  $encrypted
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy  $policy
     * @param  bool  $responseSigned
     * @param  int  $maxBytes
     * @return string
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function decrypt(EncryptedAssertion $encrypted, ResponsePolicy $policy, bool $responseSigned, int $maxBytes): string
    {
        try {
            $plaintext = self::plaintext($encrypted, $policy, $responseSigned, $maxBytes);
        } catch (\Throwable) {
            $plaintext = null;
        }

        return $plaintext ?? throw new ReadFailure(FailureReason::DECRYPTION_FAILED, 'decryption');
    }

    /**
     * The plaintext, or `null` when the policy refuses the element or nothing
     * decrypts it within the caps.
     *
     * @param  \SimpleSAML\SAML2\XML\saml\EncryptedAssertion  $encrypted
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy  $policy
     * @param  bool  $responseSigned
     * @param  int  $maxBytes
     * @return ?string
     *
     * @throws \Throwable
     */
    private static function plaintext(EncryptedAssertion $encrypted, ResponsePolicy $policy, bool $responseSigned, int $maxBytes): ?string
    {
        $data      = $encrypted->getEncryptedData();
        $algorithm = (string) $data->getEncryptionMethod()?->getAlgorithm()->getValue();
        $keys      = [...$encrypted->getEncryptedKeys(), ...$encrypted->getDecryptionKeys()];
        $cipher    = base64_decode((string) $data->getCipherData()->getCipherValue()?->getContent()->getValue(), true);

        if (!self::admitsData($algorithm, $policy, $responseSigned) || count($keys) !== 1 || !self::fits($cipher, $maxBytes + self::OVERHEAD_BYTES)) {
            return null;
        }

        $session = self::sessionKey($keys[0], $policy, self::DATA_ENCRYPTION_ALGORITHMS[$algorithm]);

        if ($session === null) {
            return null;
        }

        $plaintext = (new EncryptionAlgorithmFactory([]))->getAlgorithm($algorithm, new SymmetricKey($session))->decrypt((string) $cipher);

        return self::fits($plaintext, $maxBytes) ? $plaintext : null;
    }

    /**
     * Whether the data encryption algorithm is allowed by the connection and
     * decrypted by the package, AES-CBC only after a verified response
     * signature.
     *
     * @param  string  $algorithm
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy  $policy
     * @param  bool  $responseSigned
     * @return bool
     */
    private static function admitsData(string $algorithm, ResponsePolicy $policy, bool $responseSigned): bool
    {
        $known   = array_key_exists($algorithm, self::DATA_ENCRYPTION_ALGORITHMS);
        $allowed = in_array($algorithm, $policy->dataEncryptionAlgorithms, true);
        $ordered = $responseSigned || !in_array($algorithm, self::CBC_ALGORITHMS, true);

        return $known && $allowed && $ordered;
    }

    /**
     * The session key the encrypted key carries, decrypted by RSA-OAEP with the
     * first of the service provider's keys that yields one of the length, or
     * `null`.
     *
     * @param  \SimpleSAML\XMLSecurity\XML\xenc\EncryptedKey  $key
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy  $policy
     * @param  int  $length
     * @return ?string
     */
    private static function sessionKey(EncryptedKey $key, ResponsePolicy $policy, int $length): ?string
    {
        $transport = (string) $key->getEncryptionMethod()?->getAlgorithm()->getValue();

        if (!in_array($transport, self::KEY_TRANSPORT_ALGORITHMS, true) || !in_array($transport, $policy->keyTransportAlgorithms, true)) {
            return null;
        }

        foreach ($policy->decryptionKeys() as $privateKey) {

            $session = self::unwrapped($key, $transport, $privateKey->reveal());

            if ($session !== null && strlen($session) === $length) {
                return $session;
            }
        }

        return null;
    }

    /**
     * The session key the private key unwraps, or `null` when it does not.
     *
     * @param  \SimpleSAML\XMLSecurity\XML\xenc\EncryptedKey  $key
     * @param  string  $transport
     * @param  string  $privateKey
     * @return ?string
     */
    private static function unwrapped(EncryptedKey $key, string $transport, #[\SensitiveParameter] string $privateKey): ?string
    {
        try {
            return $key->decrypt((new KeyTransportAlgorithmFactory)->getAlgorithm($transport, new PrivateKey(PEM::fromString($privateKey))));
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Whether the bytes were decoded and are within the cap.
     *
     * @param  false|string  $bytes
     * @param  int  $maxBytes
     * @return bool
     */
    private static function fits(false|string $bytes, int $maxBytes): bool
    {
        return is_string($bytes) && $bytes !== '' && strlen($bytes) <= $maxBytes;
    }
}
