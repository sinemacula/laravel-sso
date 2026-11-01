<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Migrations\Migration;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * Creates and drops the domains table through its shipped migration, on the
 * storage connection and under its configured name, and makes claims for a test
 * to work on. A test that uses it uses `UsesConnections` too, since a claim
 * belongs to a connection.
 *
 * A test calls `createDomainsTable()` in its `setUp()` and `dropDomainsTable()`
 * in its `tearDown()`, before the parent's, so a persistent database starts the
 * next test without it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait UsesDomains
{
    /**
     * Run the domains table's shipped migration.
     *
     * @return void
     */
    protected function createDomainsTable(): void
    {
        self::domainsMigration()->up(); // @phpstan-ignore method.notFound
    }

    /**
     * Roll the domains table's shipped migration back.
     *
     * @return void
     */
    protected function dropDomainsTable(): void
    {
        self::domainsMigration()->down(); // @phpstan-ignore method.notFound
    }

    /**
     * Make and save the connection's claim of the domain: pending, claimed at
     * the clock's now with the default record name and a fixed token, expiring
     * a week later, unless the attributes given say otherwise. A `verified`
     * state given without times is verified and checked at the claim's time.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $domain
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Domain
     */
    protected function makeDomain(Connection $connection, string $domain = 'example.com', array $attributes = []): Domain
    {
        $claimedAt = CarbonImmutable::parse('2026-11-01T09:30:00Z');
        $state     = $attributes['state'] ?? DomainState::PENDING;
        $verified  = $state === DomainState::VERIFIED;

        $claim = new Domain;

        $claim->forceFill($attributes + [
            'connection_id'            => $connection->id,
            'domain'                   => $domain,
            'verified_domain'          => $verified ? $domain : null,
            'state'                    => $state,
            'record_name'              => '_sso-verification',
            'verification_token'       => str_repeat('ab', 32),
            'claimed_at'               => $claimedAt,
            'pending_expires_at'       => $verified ? null : $claimedAt->addWeek(),
            'verified_at'              => $verified ? $claimedAt : null,
            'last_successful_check_at' => $verified ? $claimedAt : null,
        ])->save();

        return $claim;
    }

    /**
     * The shipped migration of the domains table.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function domainsMigration(): Migration
    {
        return require dirname(__DIR__, 2) . '/database/migrations/2026_11_02_000000_create_sso_domains_table.php';
    }
}
