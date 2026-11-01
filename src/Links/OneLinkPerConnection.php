<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The default link limit (SSO-8.4): an identity holds at most one link in each
 * connection.
 *
 * It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OneLinkPerConnection implements LinkLimit
{
    /** @var int The most links an identity holds in a connection. */
    public const int MAX_LINKS = 1;

    /**
     * One link per connection, for every identity.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return int
     */
    #[\Override]
    public function maxLinks(IdentityReference $identity, SsoConnection $connection): int
    {
        unset($identity, $connection);

        return self::MAX_LINKS;
    }
}
