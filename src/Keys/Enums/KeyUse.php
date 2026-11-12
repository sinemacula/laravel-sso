<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys\Enums;

use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * What a row of the keys and certificates table is for: one of the service
 * provider's own key pairs, or a certificate the connection trusts.
 *
 * Stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum KeyUse: string
{
    // The SAML service provider's key pair for signing `AuthnRequest`s
    case SP_SIGNING = 'sp_signing';

    // The SAML service provider's key pair for decrypting assertions
    case SP_ENCRYPTION = 'sp_encryption';

    // The OIDC relying party's `private_key_jwt` key pair (RFC 7523)
    case CLIENT_ASSERTION = 'client_assertion';

    // A signing certificate of the identity provider that the connection trusts
    case IDP_SIGNING = 'idp_signing';

    // A certificate the identity provider's metadata must be signed by
    case METADATA_SIGNING = 'metadata_signing';

    /**
     * Whether the row is one of the service provider's own key pairs, with an
     * encrypted private key and a state.
     *
     * @return bool
     */
    public function isOwnKey(): bool
    {
        return !$this->isTrustedCertificate();
    }

    /**
     * Whether the row is a certificate the connection trusts, with no private
     * key and no state.
     *
     * @return bool
     */
    public function isTrustedCertificate(): bool
    {
        return $this === self::IDP_SIGNING || $this === self::METADATA_SIGNING;
    }

    /**
     * The protocol the use belongs to.
     *
     * @return string
     */
    public function protocol(): string
    {
        return $this === self::CLIENT_ASSERTION ? 'oidc' : 'saml2';
    }

    /**
     * The key types a row of this use may hold: RSA only for SAML, whose
     * library signs, verifies and transports keys with RSA alone.
     *
     * @return list<\SineMacula\Laravel\Sso\Keys\Enums\KeyType>
     */
    public function allowedTypes(): array
    {
        return $this === self::CLIENT_ASSERTION ? [KeyType::RSA, KeyType::EC] : [KeyType::RSA];
    }

    /**
     * The operation whose freshness a change to a row of this use needs.
     *
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation
     */
    public function freshness(): FreshnessOperation
    {
        return $this->isOwnKey() ? FreshnessOperation::KEYS_ROTATE : FreshnessOperation::CONNECTION_TRUST;
    }
}
