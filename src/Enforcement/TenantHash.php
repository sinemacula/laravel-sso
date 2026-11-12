<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

/**
 * Enforcement table key: SHA-256 of the tenant id, so a lenient column
 * collation cannot merge two tenants' rows.
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
     * Lower-case hex SHA-256 of the tenant id.
     *
     * @param  string  $tenantId
     * @return string
     */
    public static function of(string $tenantId): string
    {
        return hash('sha256', $tenantId);
    }
}
