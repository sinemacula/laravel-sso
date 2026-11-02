<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkSubject;

/**
 * Link storage contract (SSO-8.2 to SSO-8.8, `docs/design/linking.md`): a
 * `Contracts\Linker` whose resolution and whose writes are one store, in the
 * caller's transaction on the storage connection. A link written through it is
 * a link its `resolve()` answers, so nothing is ever written that the resolver
 * ignores.
 *
 * It covers what mutation and resolution must agree on:
 *
 * - ownership: `holdings()` counts what an identity holds in a connection by a
 *   locking read, and `create()` keeps the limit and the subject's uniqueness;
 * - generations: `resolve()` answers the id of the link holding a subject, and
 *   a link removed and made again has another, so continuity is compared by it;
 * - reservations: `reservations()` answers the one writer of a reserved row;
 * - confirmation and suspension: `confirm()`, `suspend()` and
 *   `revokeSessions()`, each inside the caller's transaction, under the
 *   connection's lock.
 *
 * `Links\LinkStore` implements it. A wrapper implements it by delegating every
 * method to the store it wraps, adding what it needs around them;
 * `Links\NoLinks` does not, since it links nothing. The `link` purpose, the
 * provisioning helper and linking by a verified domain each ask for it
 * (`Links\LinkStorageBinding`) and refuse with a `LogicException` before
 * writing anything when the bound `Contracts\Linker` does not implement it, and
 * the boot check reports it while the `domain_linking` feature is on.
 *
 * An implementation keeps nothing of one call for the next (SSO-11.2) and lets
 * a database error propagate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LinkStorage extends Linker
{
    /**
     * The number of links the identity holds in the connection, by a locking
     * read: active and suspended ones, and reserved ones that have not expired.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return int
     */
    public function holdings(string $connectionId, IdentityReference $identity): int;

    /**
     * Make an active link of the subject, through the connection, to the
     * identity, unless the subject is linked already or the identity holds as
     * many links in the connection as it may.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return \SineMacula\Laravel\Sso\Links\LinkCreation
     *
     * @SuppressWarnings("php:S107")
     */
    public function create(
        SsoConnection $connection,
        LinkSubject $subject,
        IdentityReference $identity,
        LinkOrigin $origin,
        ?ActingIdentity $actor = null,
        ?string $application = null,
        ?Purpose $purpose = null,
        ?RequestReference $reference = null,
    ): LinkCreation;

    /**
     * Clear the link's suspension and verified domain provenance for good, once
     * the person confirmed it, under the locks of the redemption.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $locked
     * @param  string  $linkId
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return void
     */
    public function confirm(SsoConnection $locked, string $linkId, ?string $application = null, ?RequestReference $reference = null): void;

    /**
     * Store the locked link's suspension, latched, raise the connection's links
     * version and report it.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  string  $protocol
     * @return void
     */
    public function suspend(string $linkId, IdentityReference $identity, string $connectionId, string $tenantId, string $protocol): void;

    /**
     * Revoke the sessions established through the locked link, in the caller's
     * transaction. Asking twice for one link is safe.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @return void
     */
    public function revokeSessions(string $linkId, IdentityReference $identity, string $connectionId, string $tenantId): void;

    /**
     * The one writer of a reserved row.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkReservations
     */
    public function reservations(): LinkReservations;
}
