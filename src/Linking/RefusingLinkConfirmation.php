<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;

/**
 * The default link confirmation contract: no authentication counts as
 * independent of a domain-made link.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefusingLinkConfirmation implements LinkConfirmation
{
    /**
     * Answer that the caller's session is not independent.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  list<string>  $domainLinkIds
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     */
    #[\Override]
    public function judge(Caller $caller, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict
    {
        unset($caller, $connection, $domainLinkIds);

        return LinkConfirmationVerdict::DEPENDENT;
    }
}
