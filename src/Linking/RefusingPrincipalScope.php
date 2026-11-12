<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * The default principal scope contract: it keeps no principals, so it answers
 * `unknown`, which refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefusingPrincipalScope implements PrincipalScope
{
    /**
     * Know nothing of the identity's principals.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     */
    #[\Override]
    public function judge(IdentityReference $identity, string $tenantId): ScopeVerdict
    {
        unset($identity, $tenantId);

        return ScopeVerdict::UNKNOWN;
    }
}
