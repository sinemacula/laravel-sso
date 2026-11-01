<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Enforcement;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\TenantHash;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * A session revocation that records each call: the scope, the storage
 * connection's transaction level at the time, and the version the scope's
 * tenant's row held as it was called, so a test proves the revocation ran
 * inside the change's transaction, after its write, with the policy now in
 * force.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingRevocation implements SessionRevocation
{
    /** @var list<array{scope: \SineMacula\Laravel\Sso\Revocation\RevocationScope, level: int, version: ?string}> Each call, in order. */
    private array $calls = [];

    /**
     * Record the call.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     */
    #[\Override]
    public function revoke(RevocationScope $scope): void
    {
        $version = TenantEnforcement::query()->useWritePdo()->where('tenant_hash', TenantHash::of($scope->tenantId))->value('version');

        $this->calls[] = [
            'scope'   => $scope,
            'level'   => DB::connection(StorageConnection::name())->transactionLevel(),
            'version' => is_string($version) ? $version : null,
        ];
    }

    /**
     * Each call, in order.
     *
     * @return list<array{scope: \SineMacula\Laravel\Sso\Revocation\RevocationScope, level: int, version: ?string}>
     */
    public function calls(): array
    {
        return $this->calls;
    }

    /**
     * The scope of each call, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Revocation\RevocationScope>
     */
    public function scopes(): array
    {
        return array_column($this->calls, 'scope');
    }
}
