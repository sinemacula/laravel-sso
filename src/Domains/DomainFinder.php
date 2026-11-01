<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * Finds domains for the domain helpers (SSO-3.1, SSO-3.2), always on the write
 * connection (SSO-11.3), so a claim or a verification is never judged against a
 * lagging replica.
 *
 * A connection's own claims are found through the connection, which the caller
 * found scoped to its tenant (`Connections\ConnectionFinder`), so a domain of
 * another tenant's connection is never returned. Every claim of a domain,
 * whatever its connection, is read only to decide whether another connection
 * holds it verified, and never leaves the helper. A row that does not hold
 * exactly the name and connection asked for is treated as absent, whatever the
 * column's collation.
 *
 * Under a lock, every read that decides a write is itself a locking read: a
 * plain read would answer from the snapshot of a transaction the caller opened
 * (MySQL's `REPEATABLE READ`), which may predate a change committed before the
 * lock was taken. The locks are taken in one order: the connection's row, then
 * the claims of one domain in id order. Nothing locks by `verified_domain`,
 * whose gap locks would deadlock with a verification's update on MySQL; its
 * unique index is the last guard instead. A database error propagates
 * (SSO-11.4).
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
     * Whether the row is the connection's claim of exactly the domain.
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
     * A query of the domains, on the write connection, locking what it reads
     * when asked.
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
