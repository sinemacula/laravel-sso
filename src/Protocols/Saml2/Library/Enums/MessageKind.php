<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums;

/**
 * The kind of SAML document the hardened parser reads, which names the SAML 2.0
 * schema it must be valid against (SSO-6.1, SSO-6.11): a protocol message (a
 * `Response`), an assertion decrypted from an `EncryptedAssertion`, and
 * identity provider metadata.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum MessageKind: string
{
    // A protocol message
    case PROTOCOL = 'protocol';

    // An assertion decrypted from an encrypted assertion
    case ASSERTION = 'assertion';

    // Identity provider metadata, one entity or an aggregate
    case METADATA = 'metadata';

    /**
     * The file name of the schema a document of the kind must be valid against,
     * in the library's schema directory.
     *
     * @return string
     */
    public function schema(): string
    {
        return match ($this) {
            self::PROTOCOL  => 'saml-schema-protocol-2.0.xsd',
            self::ASSERTION => 'saml-schema-assertion-2.0.xsd',
            self::METADATA  => 'saml-schema-metadata-2.0.xsd',
        };
    }
}
