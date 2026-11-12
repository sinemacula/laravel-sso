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
 * Builds a connection's `ResponsePolicy`, read afresh for each response.
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
     * A closure that reads and decrypts the private decryption keys when
     * called, so a response without an encrypted assertion decrypts none.
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
