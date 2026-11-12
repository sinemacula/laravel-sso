<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SamlConnections;

/**
 * The example application's tenant, known to the package by its opaque id.
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
