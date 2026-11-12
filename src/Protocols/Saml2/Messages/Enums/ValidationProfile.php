<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums;

/**
 * The validation profile a SAML message is checked by; parsing is shared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ValidationProfile: string
{
    // Identity provider metadata
    case METADATA = 'metadata';

    // A successful response with an `InResponseTo` somewhere
    case SOLICITED = 'solicited';

    // A non-success status; no assertion is read, only a failure code results
    case UNSUCCESSFUL = 'unsuccessful';

    // A successful response with no `InResponseTo`; only re-initiation results
    case UNSOLICITED = 'unsolicited';
}
