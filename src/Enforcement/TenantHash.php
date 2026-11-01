<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

/**
 * The key one row per tenant is kept by in the enforcement table: the
 * lower-case hex SHA-256 of the tenant's opaque id, so a column collation that
 * counts `acme` and `Acme`, or `acme` and `acme `, as equal cannot merge two
 * tenants' rows. A query by the hash still checks the row's tenant id byte for
 * byte.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TenantHash
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The hash of the tenant id.
     *
     * @param  string  $tenantId
     * @return string
     */
    public static function of(string $tenantId): string
    {
        return hash('sha256', $tenantId);
    }
}
