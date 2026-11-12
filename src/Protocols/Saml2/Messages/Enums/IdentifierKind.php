<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums;

/**
 * Which identifier a verified assertion's `Subject` carries. Only a `NameID`
 * can be a subject.
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
