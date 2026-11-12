<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;

/**
 * How many links an identity holds in a connection, and how many it may.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LinkHoldings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Count the identity's held links in the connection by a locking read.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     */
    public static function count(string $connectionId, IdentityReference $identity, CarbonImmutable $now): int
    {
        $links = Link::query()
            ->useWritePdo()
            ->where('identity_type', $identity->type)
            ->where('identity_id', $identity->id)
            ->where('connection_id', $connectionId)
            ->lockForUpdate()
            ->get()
            ->all();

        return count(array_filter($links, static fn (Link $link): bool => self::isOwnedBy($link, $identity) && self::isHeld($link, $now)));
    }

    /**
     * The binding's link limit, refused when it is below one.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\LinkLimit  $binding
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return int
     *
     * @throws \LogicException
     */
    public static function limitOf(LinkLimit $binding, IdentityReference $identity, Connection $connection): int
    {
        $limit = $binding->maxLinks($identity, $connection);

        if ($limit < 1) {
            throw new \LogicException(sprintf('The link limit [%s] answered %d; a link limit is at least one.', $binding::class, $limit));
        }

        return $limit;
    }

    /**
     * Whether the link is the identity's, byte for byte whatever the collation.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     */
    private static function isOwnedBy(Link $link, IdentityReference $identity): bool
    {
        return $link->identity_type === $identity->type && $link->identity_id === $identity->id;
    }

    /**
     * Whether the link counts toward the limit: any but an expired reservation.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    private static function isHeld(Link $link, CarbonImmutable $now): bool
    {
        if ($link->state !== LinkState::RESERVED) {
            return true;
        }

        return $link->reservation_expires_at?->isAfter($now) ?? false;
    }
}
