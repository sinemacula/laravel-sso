<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * Finds domains on the write connection, so nothing is judged against a lagging
 * replica.
 *
 * Lock the connection's row first, then one domain's claims in id order; never
 * lock by `verified_domain`, whose MySQL gap locks would deadlock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DomainFinder
{
    /**
     * The connection's claim of the normalised domain, or `null`; locked for
     * update until the caller's transaction ends when asked.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $domain
     * @param  bool  $lock
     * @return ?\SineMacula\Laravel\Sso\Models\Domain
     */
    public function find(Connection $connection, string $domain, bool $lock = false): ?Domain
    {
        $found = self::query($lock)->where('connection_id', $connection->id)->where('domain', $domain)->first();

        return self::isClaimOf($found, $connection->id, $domain) ? $found : null;
    }

    /**
     * Every claim of the normalised domain, of any connection, in id order;
     * locked for update until the caller's transaction ends when asked.
     *
     * @param  string  $domain
     * @param  bool  $lock
     * @return \SineMacula\Laravel\Sso\Domains\DomainClaims
     */
    public function claimsOf(string $domain, bool $lock = false): DomainClaims
    {
        $claims = self::query($lock)->where('domain', $domain)->orderBy('id')->get()->all();

        return new DomainClaims(array_values(array_filter($claims, static fn (Domain $claim): bool => $claim->domain === $domain)));
    }

    /**
     * Every claim of the connection, oldest first.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return list<\SineMacula\Laravel\Sso\Models\Domain>
     */
    public function forConnection(Connection $connection): array
    {
        $claims = self::query(false)->where('connection_id', $connection->id)->orderBy('created_at')->orderBy('id')->get()->all();

        return array_values(array_filter($claims, static fn (Domain $claim): bool => $claim->connection_id === $connection->id));
    }

    /**
     * Whether the row is the connection's claim of exactly the domain, whatever
     * the column's collation.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Domain  $found
     * @param  string  $connectionId
     * @param  string  $domain
     * @return bool
     */
    private static function isClaimOf(?Domain $found, string $connectionId, string $domain): bool
    {
        if ($found === null) {
            return false;
        }

        return $found->connection_id === $connectionId && $found->domain === $domain;
    }

    /**
     * A query of the domains on the write connection, locking when asked.
     *
     * @param  bool  $lock
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Sso\Models\Domain>
     */
    private static function query(bool $lock): Builder
    {
        $query = Domain::query()->useWritePdo();

        return $lock ? $query->lockForUpdate() : $query;
    }
}
