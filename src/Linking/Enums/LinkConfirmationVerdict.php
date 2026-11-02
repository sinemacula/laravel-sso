<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking\Enums;

/**
 * Whether the caller's current authentication stands apart from the links of
 * verified domain provenance its identity holds (SSO-8.8).
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum LinkConfirmationVerdict: string
{
    // The caller authenticated by something none of those links can assert
    case INDEPENDENT = 'independent';

    // It authenticated through one of them, or the contract cannot tell; the
    // default answer
    case DEPENDENT = 'dependent';

    /**
     * Whether the caller's authentication can stand as the person's own.
     *
     * @return bool
     */
    public function isIndependent(): bool
    {
        return $this === self::INDEPENDENT;
    }
}
