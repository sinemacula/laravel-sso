<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;

/**
 * Decides whether an identity may link through a connection, for example only
 * as a member of the connection's tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LinkEligibility
{
    /**
     * Asked at completion and again inside the redemption's transaction; read
     * from the write connection and let errors propagate.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict
     */
    public function judge(IdentityReference $identity, SsoConnection $connection): LinkEligibilityVerdict;
}
