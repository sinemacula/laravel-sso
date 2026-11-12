<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * A session revocation that records each scope it is asked to revoke.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordedRevocations implements SessionRevocation
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
