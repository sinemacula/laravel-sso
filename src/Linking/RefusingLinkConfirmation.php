<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;

/**
 * The default link confirmation contract (SSO-8.8): no caller's authentication
 * counts as independent of a verified domain link until the application binds
 * its own, so a `link` of an identity that holds, or has ever held, such a link
 * is refused.
 *
 * It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefusingLinkConfirmation implements LinkConfirmation
{
    /**
     * Answer that the caller's authentication is not independent.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  list<string>  $domainLinkIds
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     */
    #[\Override]
    public function judge(IdentityReference $identity, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict
    {
        unset($identity, $connection, $domainLinkIds);

        return LinkConfirmationVerdict::DEPENDENT;
    }
}
