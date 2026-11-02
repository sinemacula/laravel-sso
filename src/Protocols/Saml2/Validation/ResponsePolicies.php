<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * Builds what the SAML adapter holds one connection's response to (SSO-2.6,
 * SSO-6.2, SSO-6.7, SSO-6.8), read afresh for each response:
 *
 * - the identity provider signing certificates the connection trusts now
 *   (`KeyRing::trustedCertificates()`, `idp_signing`), the only keys any
 *   signature is verified with;
 * - the signature algorithms its settings allow, and the key transport and
 *   data encryption algorithms, AES-CBC among them only when it lists one;
 * - what yields the service provider's decryption keys: a closure over
 *   `KeyRing::decryption()` that reads them and decrypts each private key only
 *   when the adapter asks, which it does only for an encrypted assertion, so a
 *   response carrying none never decrypts a stored key.
 *
 * It holds the key ring alone, which keeps nothing between calls (SSO-11.2). A
 * database error propagates (SSO-11.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResponsePolicies
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     */
    public function __construct(

        /** The connection's trusted certificates and decryption keys. */
        private KeyRing $keys,
    ) {}

    /**
     * The policy the connection holds a response to now.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy
     *
     * @throws \InvalidArgumentException
     */
    public function policy(SsoConnection $connection, Saml2Options $options): ResponsePolicy
    {
        $id = $connection->getConnectionId();

        return new ResponsePolicy(
            self::certificates($this->keys->trustedCertificates($id, KeyUse::IDP_SIGNING)),
            $options->listOf(Saml2Setting::SIGNATURE_ALGORITHMS),
            $options->keyTransportAlgorithms(),
            $options->dataEncryptionAlgorithms(),
            self::decryptionKeys($this->keys, $id),
        );
    }

    /**
     * The PEM certificate of each trusted certificate, in the key ring's order.
     *
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $trusted
     * @return list<string>
     */
    private static function certificates(array $trusted): array
    {
        $certificates = array_map(static fn (KeySummary $key): ?string => $key->key->certificate, $trusted);

        return array_values(array_filter($certificates, is_string(...)));
    }

    /**
     * What reads the connection's decryption keys and decrypts their private
     * halves, once it is called.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     * @param  string  $connectionId
     * @return \Closure(): list<\SineMacula\Laravel\Sso\Secrets\Secret>
     */
    private static function decryptionKeys(KeyRing $keys, string $connectionId): \Closure
    {
        return static fn (): array => array_map(
            static fn (KeySummary $key): Secret => $keys->privateKey($connectionId, $key->id),
            $keys->decryption($connectionId),
        );
    }
}
