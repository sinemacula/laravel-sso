<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkSubject;

/**
 * A `Contracts\Linker` whose resolution and writes are one store, so nothing is
 * written that the resolver ignores.
 *
 * Every write runs in the caller's transaction on the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LinkStorage extends Linker
{
    /**
     * Count active, suspended and unexpired reserved links by a locking read.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return int
     */
    public function holdings(string $connectionId, IdentityReference $identity): int;

    /**
     * Link the subject to the identity unless the subject is linked already or
     * the identity is at its link limit.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
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
        ClientContext $client,
        ?Caller $caller = null,
        ?string $application = null,
        ?Purpose $purpose = null,
        ?RequestReference $reference = null,
    ): LinkCreation;

    /**
     * Clear the link's suspension and domain provenance for good, under the
     * redemption's locks.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $locked
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return void
     */
    public function confirm(SsoConnection $locked, string $linkId, ClientContext $client, ?string $application = null, ?RequestReference $reference = null): void;

    /**
     * Latch the locked link's suspension and raise the connection's links
     * version.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  string  $protocol
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     */
    public function suspend(string $linkId, IdentityReference $identity, string $connectionId, string $tenantId, string $protocol, ClientContext $client): void;

    /**
     * Revoke the sessions established through the locked link, idempotently.
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
