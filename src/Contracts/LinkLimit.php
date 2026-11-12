<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Caps how many links, active and reserved together, an identity may hold in
 * one connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LinkLimit
{
    /**
     * Answer at least one; a lower answer is a `LogicException`.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return int
     */
    public function maxLinks(IdentityReference $identity, SsoConnection $connection): int;
}
