<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\ManagingConnections;

use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * The example application's session revocation, which records each scope it is
 * asked to revoke (SSO-4.5): an application deletes the sessions of the scope
 * here, in the package's transaction, and a test reads what the package asked
 * of it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RevokedSessions implements SessionRevocation
{
    /** @var list<\SineMacula\Laravel\Sso\Revocation\RevocationScope> Each scope revoked, in order. */
    private array $revoked = [];

    /**
     * Record the scope.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     */
    #[\Override]
    public function revoke(RevocationScope $scope): void
    {
        $this->revoked[] = $scope;
    }

    /**
     * Each scope revoked, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Revocation\RevocationScope>
     */
    public function revoked(): array
    {
        return $this->revoked;
    }
}
