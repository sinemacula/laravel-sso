<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The example application's link limit (SSO-8.4): an identity may hold two
 * links in one connection, where the package's default allows one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TwoLinksPerConnection implements LinkLimit
{
    // @snippet-start links-limit
    /**
     * The most links the identity may hold in the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return int
     */
    #[\Override]
    public function maxLinks(IdentityReference $identity, SsoConnection $connection): int
    {
        // The same for every identity and connection
        unset($identity, $connection);

        return 2;
    }
    // @snippet-end links-limit
}
