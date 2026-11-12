<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Handoffs\RecheckLock;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;

/**
 * Whether a `link` redemption may go on, given the identity's domain-made
 * links, held now or ever.
 *
 * Hold the identity's guard first, so a domain-made provider cannot clear its
 * own provenance.
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
     * The connections holding the identity's domain-made links, by a plain
     * read: locking here would lock links before connections.
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
     * The identity's domain-made link ids by a locking read; one in an unlocked
     * connection means retry the whole transaction.
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
     * Whether the identity never held such a link, or the caller's session is
     * independent of them.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  list<string>  $held
     * @param  bool  $heldBefore
     * @return bool
     */
    public function allows(Caller $caller, Connection $connection, array $held, bool $heldBefore): bool
    {
        return ($held === [] && !$heldBefore) || $this->confirmation->judge($caller, $connection, $held)->isIndependent();
    }

    /**
     * The identity's active and suspended domain-made links; a reservation
     * carries no session yet.
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
