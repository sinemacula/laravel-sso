<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * Makes domain claims for a test to work on. A test that uses it uses
 * `UsesConnections` too, since a claim belongs to a connection, and calls
 * `usePackageTables()` in its `setUp()`, so the tables exist.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait UsesDomains
{
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
}
