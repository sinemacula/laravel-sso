<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums;

/**
 * Which identifier a verified assertion's `Subject` carries (SAML 2.0 Core
 * §2.4.1): a `NameID`, the only one that may be a subject (SSO-6.9); a `BaseID`
 * or an `EncryptedID`, which the package never decrypts or reads; or none,
 * which a subject taken from an attribute allows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum IdentifierKind: string
{
    // A name identifier
    case NAME_ID = 'name_id';

    // A base identifier, never read
    case BASE_ID = 'base_id';

    // An encrypted identifier, never decrypted
    case ENCRYPTED_ID = 'encrypted_id';

    // No identifier
    case NONE = 'none';
}
