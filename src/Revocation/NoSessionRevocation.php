<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Revocation;

use SineMacula\Laravel\Sso\Contracts\SessionRevocation;

/**
 * The default session revocation (SSO-4.5): it revokes nothing.
 *
 * The package holds no sessions, so alone it cannot revoke one. With this
 * default, an enforcement change, a disabled or deleted connection and a
 * removed link leave every existing session as it was; only sessions
 * established afterwards are judged by the new state. An application that keeps
 * sessions binds its own contract, or an adapter binds the revocation of the
 * application's authentication, which an enforcement change needs.
 *
 * It holds nothing, so it is bound as a singleton.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoSessionRevocation implements SessionRevocation
{
    /**
     * Revoke nothing, and succeed.
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
