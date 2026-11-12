<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results\Enums;

/**
 * Whether the identity provider's session deadline limits the application's
 * session or is kept as provenance only.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum DeadlineEffect: string
{
    // The application's session ends no later than the deadline; the default
    case LIMITS_SESSION = 'limits_session';

    // The deadline is kept as provenance and limits nothing
    case IGNORED = 'ignored';

    /**
     * Whether the deadline limits the application's session.
     *
     * @return bool
     */
    public function limitsSession(): bool
    {
        return $this === self::LIMITS_SESSION;
    }
}
