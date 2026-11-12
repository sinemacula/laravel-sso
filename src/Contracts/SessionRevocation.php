<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * Revokes the application's sessions that a change in this package leaves out
 * of compliance.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SessionRevocation
{
    /**
     * Write through the caller's transaction on the storage connection, be
     * idempotent, and throw on failure so the change rolls back. Without a
     * record of a session's link, revoke the identity's sessions through the
     * connection: broader, never narrower.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     */
    public function revoke(RevocationScope $scope): void;
}
