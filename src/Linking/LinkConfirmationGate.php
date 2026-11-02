<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Handoffs\RecheckLock;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;

/**
 * Whether a `link` redemption may go on, as far as the verified domain links of
 * its identity are concerned (SSO-8.8): an identity that has never held an
 * active one is not asked about, and any other needs
 * `Contracts\LinkConfirmation` to answer `independent`. So an identity provider
 * that captured a person by a verified domain cannot clear that provenance
 * itself, nor add a second subject, in any connection, with no such provenance.
 *
 * Removing the link does not make what survives of its session independent
 * either. Whether the identity has ever held such a link is recorded on its
 * guard when a reservation is activated, and never cleared
 * (`Linking\IdentityLock::hasHeldDomainLink()`): once it has, the contract is
 * asked even when no such link remains, with the ones that do, possibly none.
 * Its answer is about how the caller's session was established, not what links
 * remain.
 *
 * The order is the package's (`docs/design/linking.md`). The identity's guard
 * comes first (`Linking\IdentityLock`), so no reservation, activation, widening
 * or other confirmation of that identity runs alongside, which is what protects
 * a link row that does not exist yet. `connectionsHolding()` then finds, by a
 * plain read, which connections hold those links, and `Handoffs\HandoffRecheck`
 * locks them, in id order, with the others. `lockedDomainLinks()` reads the
 * links by a locking read under those locks, before any application contract is
 * asked, so the application's guards come after the package's. A link found in
 * a connection that was not locked is `Exceptions\LinkCandidatesChanged`: that
 * connection cannot be locked now without breaking the order. Only a
 * transaction whose snapshot predates the guard can come to it, such as a
 * caller's that read before it redeemed, under MySQL's `REPEATABLE READ`; the
 * caller retries its whole transaction. The package's standalone redemption
 * takes the guard before any read of its own, and restarts once if it comes to
 * it all the same (`Handoffs\HandoffRedemption`).
 *
 * A reserved row is left out, since no session stands on it yet. Links are
 * compared byte for byte. It holds the contract, which keeps nothing of one
 * redemption for the next (SSO-11.2). A contract's exception propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkConfirmationGate
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\LinkConfirmation  $confirmation
     */
    public function __construct(

        /** Whether the caller's authentication stands apart from the links. */
        private LinkConfirmation $confirmation,
    ) {}

    /**
     * The ids of the connections holding the identity's active and suspended
     * links of verified domain provenance, by a plain read, once its guard is
     * held. Plain, since a locking read here would lock link rows before their
     * connections.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return list<string>
     */
    public static function connectionsHolding(IdentityReference $identity): array
    {
        $owned = self::owned(self::domainLinks($identity)->get()->all(), $identity);

        return array_values(array_unique(array_map(static fn (Link $link): string => $link->connection_id, $owned)));
    }

    /**
     * The ids of the identity's active and suspended links of verified domain
     * provenance, in id order, by a locking read under the guard and the
     * connections' locks.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @return list<string>
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged
     */
    public function lockedDomainLinks(IdentityReference $identity, RecheckLock $lock): array
    {
        if (!$lock->isGuarding($identity)) {
            throw new \LogicException('A [link] redemption locks with the identity it was started for: pass it to HandoffRecheck::lock().');
        }

        $owned = self::owned(self::domainLinks($identity)->orderBy('id')->lockForUpdate()->get()->all(), $identity);

        foreach ($owned as $link) {

            if (!$lock->covers($link->connection_id)) {
                throw LinkCandidatesChanged::retryWhole();
            }
        }

        return array_map(static fn (Link $link): string => $link->id, $owned);
    }

    /**
     * Whether the identity has never held such a link, or the caller's
     * authentication is independent of those it holds and held.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  list<string>  $held
     * @param  bool  $heldBefore
     * @return bool
     */
    public function allows(IdentityReference $identity, Connection $connection, array $held, bool $heldBefore): bool
    {
        return ($held === [] && !$heldBefore) || $this->confirmation->judge($identity, $connection, $held)->isIndependent();
    }

    /**
     * The query of the identity's active and suspended links of verified domain
     * provenance, on the write connection.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Sso\Models\Link>
     */
    private static function domainLinks(IdentityReference $identity): Builder
    {
        return Link::query()
            ->useWritePdo()
            ->where('identity_type', $identity->type)
            ->where('identity_id', $identity->id)
            ->where('provenance', LinkOrigin::VERIFIED_DOMAIN->value)
            ->whereIn('state', [LinkState::ACTIVE->value, LinkState::SUSPENDED->value]);
    }

    /**
     * The links that are the identity's, byte for byte, whatever the collation.
     *
     * @param  array<int, \SineMacula\Laravel\Sso\Models\Link>  $links
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return list<\SineMacula\Laravel\Sso\Models\Link>
     */
    private static function owned(array $links, IdentityReference $identity): array
    {
        return array_values(array_filter($links, static fn (Link $link): bool => $link->identity_type === $identity->type && $link->identity_id === $identity->id));
    }
}
