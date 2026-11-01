<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Discovery;

use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Domains\DomainFinder;
use SineMacula\Laravel\Sso\Domains\DomainName;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * Resolves an email address to the connection its domain routes discovery to
 * (SSO-3.4), from the domain alone: it never looks up a user, and reads nothing
 * but the domains and the connections, both on the write connection (SSO-11.3).
 *
 * The domain is the part after the last `@`, normalised as every claim is
 * (`Domains\DomainName::normalize()`: IDNA, lower case, no trailing dot). Its
 * claims, of every connection, are read by `Domains\DomainFinder::claimsOf()`
 * without a lock, and the claim that routes it is the one for which
 * `Domains\DomainStanding::routes()` holds at the clock's now
 * (`DomainClaims::routing()`): verified, and before the end of the grace period
 * a recheck started when the record went. The unique index on `verified_domain`
 * holds at most one verified claim across every tenant, so at most one claim
 * routes a domain. Its connection must then be usable
 * (`ProtocolManager::isUsable()`: enabled, its protocol on, its settings
 * complete).
 *
 * Every other case is `null`, the same as an unknown domain, so a caller cannot
 * tell them apart: an email with no `@` or nothing after it, a domain that does
 * not normalise (a refusal is `null`, never an exception), a pending, lapsed or
 * past-grace claim, a subdomain of a verified domain (claims are exact), a
 * connection deleted, disabled or incomplete. A database error propagates
 * (SSO-11.4).
 *
 * Both sides of the comparison are normalised lower-case ASCII, so no column
 * collation can fold one name into another.
 *
 * It holds the domain lookup, the drivers and the clock, none of which keeps
 * anything of one request for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DomainRouter
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainFinder  $finder
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Reads every claim of a domain, on the write connection. */
        private DomainFinder $finder,

        /** Whether the connection a domain routes to is usable. */
        private ProtocolManager $protocols,

        /** The clock a claim's grace period is judged against. */
        private Clock $clock,
    ) {}

    /**
     * The normalised domain of the email: the part after its last `@`, or
     * `null` when it has none or that part does not normalise.
     *
     * @param  string  $email
     * @return ?string
     */
    public static function domainOf(#[\SensitiveParameter] string $email): ?string
    {
        $at = strrpos($email, '@');

        return $at === false ? null : DomainName::normalize(substr($email, $at + 1));
    }

    /**
     * The usable connection the email's domain routes discovery to, or `null`
     * when there is none.
     *
     * @param  string  $email
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     */
    public function connectionFor(#[\SensitiveParameter] string $email): ?Connection
    {
        $domain = self::domainOf($email);
        $claim  = $domain === null ? null : $this->finder->claimsOf($domain)->routing($this->clock->now());

        return $claim === null ? null : $this->usableConnection($claim->connection_id);
    }

    /**
     * The connection of the id, read from the write connection, when it exists
     * and is usable.
     *
     * @param  string  $connectionId
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     */
    private function usableConnection(string $connectionId): ?Connection
    {
        $connection = Connection::query()->useWritePdo()->whereKey($connectionId)->first();

        return $connection !== null && $this->protocols->isUsable($connection) ? $connection : null;
    }
}
