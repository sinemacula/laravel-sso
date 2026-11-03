<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;

/**
 * Enforcement contract (SSO-4.1, SSO-4.2, SSO-4.6, SSO-9.3): whether sessions
 * active in a tenant, on an application, must be established through one of the
 * connections of the tenant whose rule applies, which connections satisfy it,
 * and the version of that rule.
 *
 * It answers from the current stored state, read from the write connection and
 * never from a cache, every time it is asked, so a missed event never preserves
 * access. An adapter folds it into the tenant authentication policy of the
 * application's sessions, asked at sign-in, at the choice of principal, on
 * every switch and on refresh; redeeming a handoff code rechecks it.
 *
 * The default, `Enforcement\DatabaseEnforcement`, reads the package's
 * enforcement table for the tenant `Contracts\EnforcementInheritance` names,
 * and answers that nothing is required while the `enforcement` feature is off.
 * A database error propagates as a server error (SSO-11.4); it never answers
 * "not required" when it cannot tell. An empty or overlong tenant id, or an
 * empty application, is the caller's mistake (`InvalidArgumentException`). An
 * implementation keeps nothing of one call for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Enforcement
{
    /**
     * The enforcement that applies to sessions active in the tenant, on the
     * application.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     *
     * @throws \InvalidArgumentException
     */
    public function policy(string $tenantId, string $application): EnforcementPolicy;
}
