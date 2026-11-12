<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The default link limit: at most one link per identity in each connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OneLinkPerConnection implements LinkLimit
{
    /** @var int The most links an identity holds in a connection. */
    public const int MAX_LINKS = 1;

    /**
     * One link, for every identity and connection.
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
