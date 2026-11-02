<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * Session revocation contract (SSO-4.5, SSO-9.3): revokes the application's
 * sessions that a change in this package leaves out of compliance, inside the
 * transaction that makes the change, so the change and the revocation succeed
 * or fail together.
 *
 * The package calls it synchronously, on the storage connection's open
 * transaction, with one of four scopes (`Revocation\RevocationScope`): a tenant
 * whose enforcement changed (the sessions the policy now in force no longer
 * allows), a connection disabled or deleted (every session established through
 * it), an identity whose link through a connection was removed (its sessions
 * established through it), or an identity whose scope widened
 * (`RevocationScope::identityLink()`, reason `scope_widened`: its sessions
 * established through that one link by a verified domain, and no others). An
 * implementation handles every kind; the last needs it to record which link
 * established a session. An implementation writes through that same Laravel
 * connection, so its writes commit or roll back with the change; one that
 * writes elsewhere is not atomic with it. It signals failure by throwing: the
 * exception rolls the change back and propagates as a server error. It never
 * reports success it did not achieve. It is idempotent: a widened scope revokes
 * through one link from the principal's change and again from a resolution that
 * finds it first.
 *
 * The default, `Revocation\NoSessionRevocation`, does nothing: an application
 * without `laravel-authentication` binds its own, or accepts that existing
 * sessions are untouched by an enforcement change, a disabled or deleted
 * connection, a removed link or a widened scope. `laravel-iam` binds it to
 * `laravel-authentication`'s revocation (AUTH-2.12, AUTH-6.4, AUTH-6.5), which
 * is mandatory for an enforcement change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SessionRevocation
{
    /**
     * Revoke the sessions of the scope, inside the caller's transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     */
    public function revoke(RevocationScope $scope): void;
}
