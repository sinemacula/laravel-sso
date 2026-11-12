<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SamlMetadata;

/**
 * The example application's tenant, known to the package only by its id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Tenant
{
    /**
     * Name the tenant by its id.
     *
     * @param  string  $id
     */
    public function __construct(

        /** The tenant's id, as the application stores it. */
        public string $id,
    ) {}
}
