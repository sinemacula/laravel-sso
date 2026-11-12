<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;

/**
 * Makes a tenant's enforcement for a test to work on. A test that uses it calls
 * `usePackageTables()` in its `setUp()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait UsesEnforcement
{
    /**
     * Make and save `tenant-1`'s enforcement, off, unless overridden.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\TenantEnforcement
     */
    protected function makeEnforcement(array $attributes = []): TenantEnforcement
    {
        $enforcement = new TenantEnforcement;

        $enforcement->forceFill($attributes + [
            'tenant_id'      => 'tenant-1',
            'enabled'        => false,
            'connection_ids' => [],
            'version'        => strtolower((string) Str::ulid()),
            'changed_at'     => CarbonImmutable::parse('2026-11-01T09:30:00Z'),
        ])->save();

        return $enforcement;
    }
}
