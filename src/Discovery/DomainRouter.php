<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Discovery;

use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Domains\DomainFinder;
use SineMacula\Laravel\Sso\Domains\DomainName;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * Resolves an email address to the usable connection its domain routes
 * discovery to, from the domain alone and never a user.
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
     * The normalised part after the email's last `@`, or `null` when there is
     * none or it does not normalise.
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
     * The usable connection the email's domain routes to, or `null`.
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
     * The connection of the id, read from the write connection, when it is
     * usable.
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
