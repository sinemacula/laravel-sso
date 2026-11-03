<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\LinkingByDomain;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;

/**
 * The example application's principal mutation (SSO-8.8): granting a user a
 * principal of a tenant, or a platform principal, in one transaction on the
 * package's storage connection that first reports the widened scope, so the
 * user's links by a verified domain in every other tenant's connections are
 * suspended, and the sessions established through them revoked, with the
 * principal or not at all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantPrincipal
{
    /**
     * Grant the user a principal of the tenant, or a platform principal when
     * the tenant is `null`.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $tenantId
     * @return void
     *
     * @throws \Throwable
     */
    public function __invoke(IdentityReference $identity, ?string $tenantId): void
    {
        // @snippet-start scope-widening
        DB::connection(StorageConnection::name())->transaction(function () use ($identity, $tenantId): void {
            $widening = app(ScopeWidening::class);

            // First the identity's guard, held until this commits; the tenant
            // is `null` for a platform principal
            $widening->widened($identity, $tenantId);

            // Then your principal guard, then the write
            $this->lockPrincipals($identity);
            $this->addPrincipal($identity, $tenantId);
        });
        // @snippet-end scope-widening
    }

    /**
     * Take the guard every writer of the user's principals takes.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function lockPrincipals(IdentityReference $identity): void
    {
        if (!Users::hasLockedUser($identity)) {
            throw new \InvalidArgumentException('The identity is not one of the application\'s users.');
        }
    }

    /**
     * Write the principal, granted by an administrator and so not yet accepted
     * by the person.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $tenantId
     * @return void
     */
    private function addPrincipal(IdentityReference $identity, ?string $tenantId): void
    {
        DB::connection(StorageConnection::name())->table(Users::PRINCIPALS)->insert([
            'user_id'   => $identity->id,
            'tenant_id' => $tenantId,
        ]);
    }
}
