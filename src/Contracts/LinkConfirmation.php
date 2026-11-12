<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;

/**
 * Decides whether the caller redeeming a `link` authenticated independently of
 * the verified domain links its identity holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LinkConfirmation
{
    /**
     * Judge the caller's session, not the current request; answer `dependent`
     * when unsure or when the answer cannot be guarded until commit.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  list<string>  $domainLinkIds
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     */
    public function judge(Caller $caller, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict;
}
