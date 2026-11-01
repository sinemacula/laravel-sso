<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Link limit contract (SSO-8.4): how many links an identity may hold in one
 * connection, active and reserved together. Uniqueness of connection, issuer
 * and subject is not configurable and is not this contract's: one subject is
 * linked to one identity at most, whatever the limit.
 *
 * The default, `Links\OneLinkPerConnection`, allows one. The link store asks it
 * under the lock that serialises link creation in the connection, and treats an
 * answer below one as a misconfigured binding (`LogicException`). An
 * implementation keeps nothing of one call for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LinkLimit
{
    /**
     * The most links the identity may hold in the connection, at least one.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return int
     */
    public function maxLinks(IdentityReference $identity, SsoConnection $connection): int;
}
