<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OidcConnections;

/**
 * The example application's tenant (SSO-2.1): the organisation whose OIDC
 * connection its administration screens set up, known to the package only by
 * its opaque string id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Tenant
{
    /**
     * Constructor.
     *
     * @param  string  $id
     */
    public function __construct(

        /** The tenant's id, as the application stores it. */
        public string $id,
    ) {}
}
