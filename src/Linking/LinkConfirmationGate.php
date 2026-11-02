<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;

/**
 * Whether a `link` redemption may go on, as far as the verified domain links of
 * its identity are concerned (SSO-8.8): an identity holding none is not asked
 * about, and any other needs `Contracts\LinkConfirmation` to answer
 * `independent`. So an identity provider that captured a person by a verified
 * domain cannot clear that provenance itself, nor add a second subject, in any
 * connection, with no such provenance.
 *
 * The identity's links are read by a locking read in id order, in every
 * connection, compared byte for byte, before the subject's own link is read:
 * two `link` redemptions of one identity through different connections meet at
 * the first link they share and never lock those links in opposite orders. A
 * reserved row is left out, since no session stands on it yet.
 *
 * It holds the contract, which keeps nothing of one redemption for the next
 * (SSO-11.2). A contract's exception propagates.
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
     * Whether the identity holds no verified domain link, or the caller's
     * authentication is independent of those it holds.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    public function allows(IdentityReference $identity, Connection $connection): bool
    {
        $held = self::domainLinkIds($identity);

        return $held === [] || $this->confirmation->judge($identity, $connection, $held)->isIndependent();
    }

    /**
     * The ids of the identity's active and suspended links of verified domain
     * provenance, in id order, by a locking read on the write connection.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return list<string>
     */
    private static function domainLinkIds(IdentityReference $identity): array
    {
        $links = Link::query()
            ->useWritePdo()
            ->where('identity_type', $identity->type)
            ->where('identity_id', $identity->id)
            ->where('provenance', LinkOrigin::VERIFIED_DOMAIN->value)
            ->whereIn('state', [LinkState::ACTIVE->value, LinkState::SUSPENDED->value])
            ->orderBy('id')
            ->lockForUpdate()
            ->get()
            ->all();

        $owned = array_filter($links, static fn (Link $link): bool => $link->identity_type === $identity->type && $link->identity_id === $identity->id);

        return array_values(array_map(static fn (Link $link): string => $link->id, $owned));
    }
}
