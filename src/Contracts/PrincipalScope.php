<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * Principal scope contract (SSO-8.8): judges an identity's complete, current
 * set of principals against a tenant. Every principal must be a membership of
 * that tenant; a platform principal or a membership of any other tenant is
 * outside it, and a set the implementation cannot read completely is `unknown`,
 * which refuses.
 *
 * It is asked before a reservation, at its redemption, and whenever a link with
 * verified domain provenance resolves. On such a link:
 *
 * - `outside_tenant` latches it suspended until a confirming `link`, so
 *   removing the principal later never restores it, and revokes the sessions
 *   established through it, in the same transaction;
 * - `unknown` refuses that attempt with `principal_scope_unknown`. It asserts
 *   no widening, so it creates no suspension and revokes nothing, and a link
 *   already suspended stays suspended;
 * - an implementation whose store cannot be reached for the moment throws
 *   instead, which refuses nothing and suspends nothing.
 *
 * Protection through admission: checks at completion and at redemption cannot
 * see a principal added and removed between them, so the application's
 * principal mutation must also participate. A change that widens a person's
 * scope calls `Linking\ScopeWidening::widened()` first in its own transaction,
 * on the package's storage connection, which takes the identity's guard, the
 * first lock of the package's order, holds it until that transaction ends,
 * suspends the identity's domain links and revokes the sessions established
 * through them. It then takes the guard this contract documents to the
 * redeemer, after the package's locks, and writes the principal
 * (`docs/guides/linking-by-domain.md`). A reservation, an activation and a
 * confirmation of that identity hold its guard too, so an answer given to one
 * of them holds until it commits. An answer to an ordinary sign-in holds no
 * guard: the principal mutation's revocation, or the next resolution's, covers
 * it.
 *
 * The default, `Linking\RefusingPrincipalScope`, answers `unknown`. An
 * implementation reads from the write connection (SSO-11.3), keeps nothing of
 * one call for the next (SSO-11.2), and lets an error propagate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PrincipalScope
{
    /**
     * Where the identity's complete set of principals stands against the
     * tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     */
    public function judge(IdentityReference $identity, string $tenantId): ScopeVerdict;
}
