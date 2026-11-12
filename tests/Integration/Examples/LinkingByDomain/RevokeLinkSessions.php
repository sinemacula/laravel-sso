<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\LinkingByDomain;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * The example application's session revocation, writing through the package's
 * storage connection so it commits or rolls back with the change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RevokeLinkSessions implements SessionRevocation
{
    /** @var string The application's table of sessions. */
    public const string TABLE = 'user_sessions';

    /**
     * Revoke the sessions of the scope, inside the package's transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     */
    #[\Override]
    public function revoke(RevocationScope $scope): void
    {
        $sessions = DB::connection(StorageConnection::name())->table(self::TABLE)->whereNull('revoked_at');

        $revoked = match ($scope->kind) {
            RevocationScopeKind::TENANT => $sessions->where('tenant_id', $scope->tenantId)
                ->where(static fn (Builder $query): Builder => $query->whereNull('sso_connection_id')
                    ->orWhereNotIn('sso_connection_id', $scope->policy->connectionIds ?? [])),
            RevocationScopeKind::CONNECTION => $sessions->where('sso_connection_id', $scope->connectionId),
            default                         => $sessions->where('sso_link_id', $scope->linkId),
        };

        $revoked->update(['revoked_at' => now(), 'revoked_reason' => $scope->reason->value]);
    }
}
