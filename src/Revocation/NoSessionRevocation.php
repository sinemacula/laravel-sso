<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Revocation;

use SineMacula\Laravel\Sso\Contracts\SessionRevocation;

/**
 * The default session revocation: revokes nothing, since the package holds no
 * sessions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoSessionRevocation implements SessionRevocation
{
    /**
     * Revoke nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     */
    #[\Override]
    public function revoke(RevocationScope $scope): void
    {
        // Nothing to revoke: the package keeps no sessions of its own
    }
}
