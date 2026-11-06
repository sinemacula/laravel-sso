<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Makes connections for a test to work on. A test that uses it calls
 * `usePackageTables()` in its `setUp()`, so the tables exist.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait UsesConnections
{
    /**
     * Make and save a connection: an OIDC connection of `tenant-1` named
     * `Example`, disabled, with no settings or mapping, unless the attributes
     * given say otherwise.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    protected function makeConnection(array $attributes = []): Connection
    {
        $connection = new Connection;

        $connection->forceFill($attributes + [
            'tenant_id'    => 'tenant-1',
            'protocol'     => 'oidc',
            'display_name' => 'Example',
        ])->save();

        return $connection;
    }
}
