<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * Judges whether every one of an identity's current principals is a membership
 * of a tenant.
 *
 * A principal change that widens scope calls `Linking\ScopeWidening::widened()`
 * first, in its own transaction on the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PrincipalScope
{
    /**
     * Answer `unknown` for a set that cannot be read completely; throw when the
     * store is unreachable.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     */
    public function judge(IdentityReference $identity, string $tenantId): ScopeVerdict;
}
