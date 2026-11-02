<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;

/**
 * What an application's principal mutation calls when a person comes to hold a
 * principal (SSO-8.8, `docs/guides/linking-by-domain.md`): checks at completion
 * and at redemption cannot see a principal added and removed between them, so
 * the change itself reports it, in its own transaction. It is the primary place
 * sessions are revoked for a widened scope.
 *
 * The application calls `widened()` first in the transaction that changes the
 * person's principals, on the storage connection, given the identity and the
 * tenant of the new principal, `null` for a platform principal; then takes the
 * guard `Contracts\PrincipalScope` documents, writes the principal, and
 * commits:
 *
 * ```php
 * DB::connection($storage)->transaction(function () use ($widening, $identity, $tenantId): void {
 *     $widening->widened($identity, $tenantId);
 *     // take the guard the principal scope contract documents; write the principal
 * });
 * ```
 *
 * It takes the identity's guard first (`Linking\IdentityLock`) and holds it
 * until that transaction ends. A reservation, an activation and a confirmation
 * of the identity take the same guard first, so each runs wholly before this
 * change, and is found here, or wholly after it, and sees the principal
 * written. Nothing can slip in between, whatever the isolation level. For each
 * connection of another tenant holding one of the identity's links by a
 * verified domain, in ascending id order:
 *
 * - an active link is suspended: stored, latched
 *   (`Contracts\LinkStorage::suspend()`, which raises the connection's links
 *   version and reports `LinkSuspended` after commit), so removing the
 *   principal later never restores it;
 * - a live or expired reservation is deleted, raising the links version, so one
 *   reserved before the principal was added cannot activate once it is removed;
 * - the sessions established through each active or already suspended link are
 *   revoked through `Contracts\SessionRevocation`, in that same transaction,
 *   with `RevocationScope::identityLink()` and the reason `scope_widened`, with
 *   no second event for a link suspended earlier.
 *
 * A connection of the new principal's tenant is left alone: the principal is
 * inside it. Tenants are opaque, and compared exactly.
 *
 * The lock order is the package's: identity guard, connections ascending,
 * links, then the application's guards. Which connections hold the identity's
 * rows is found by a plain read once the guard is held, since locking link rows
 * before their connections would break that order; those connections are locked
 * in one statement, and the rows are then read again by a locking read. A row
 * in a connection that was not locked, which only a transaction with an older
 * snapshot can come to, is `Exceptions\LinkCandidatesChanged`, and the
 * application retries its whole transaction. Under PostgreSQL's
 * `REPEATABLE READ` such a transaction fails to serialise at the guard instead.
 *
 * A linker not backed by `Contracts\LinkStorage` holds no such link, so with
 * one bound only the guard is taken. Called with no transaction open on the
 * storage connection it is a `LogicException`: a suspension that commits apart
 * from the change could leave one without the other. A database error and a
 * revocation's exception propagate and roll the change back (SSO-11.4). It
 * holds the binding and the lock, neither of which keeps anything of one change
 * for the next (SSO-11.2). Resolve it from the container per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ScopeWidening
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkStorageBinding  $storage
     * @param  \SineMacula\Laravel\Sso\Linking\IdentityLock  $identities
     */
    public function __construct(

        /** Stores and reports each suspension. */
        private LinkStorageBinding $storage,

        /** Holds the identity's linking changes apart from this one. */
        private IdentityLock $identities,
    ) {}

    /**
     * Take the identity's guard; suspend its links by a verified domain in
     * every connection of another tenant than the new principal's, delete its
     * reservations in them, and revoke the sessions established through those
     * links; answer how many links this suspended.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $tenantId
     * @return int
     *
     * @throws \LogicException
     */
    public function widened(IdentityReference $identity, ?string $tenantId): int
    {
        if (DB::connection(StorageConnection::name())->transactionLevel() === 0) {
            throw new \LogicException('A widened scope is reported inside the transaction that changes the person\'s principals, on the storage connection (decision D5).');
        }

        $this->identities->acquire($identity);

        $storage = $this->storage->find();

        return $storage === null ? 0 : $this->suspended($storage, $identity, $tenantId);
    }

    /**
     * The query of the identity's links by a verified domain, on the write
     * connection, whatever the state.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Sso\Models\Link>
     */
    private static function rowsOf(IdentityReference $identity): Builder
    {
        return Link::query()->useWritePdo()
            ->where('identity_type', $identity->type)
            ->where('identity_id', $identity->id)
            ->where('provenance', LinkOrigin::VERIFIED_DOMAIN->value);
    }

    /**
     * The rows that are the identity's, byte for byte, whatever the collation.
     *
     * @param  array<int, \SineMacula\Laravel\Sso\Models\Link>  $rows
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return list<\SineMacula\Laravel\Sso\Models\Link>
     */
    private static function owned(array $rows, IdentityReference $identity): array
    {
        return array_values(array_filter($rows, static fn (Link $row): bool => $row->identity_type === $identity->type && $row->identity_id === $identity->id));
    }

    /**
     * The connections holding the rows found by a plain read, locked in one
     * statement in ascending id order.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\Link>  $rows
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     */
    private static function lockedConnections(array $rows): array
    {
        $ids = array_values(array_unique(array_map(static fn (Link $row): string => $row->connection_id, $rows)));

        sort($ids, SORT_STRING);

        return $ids === [] ? [] : array_values(Connection::query()->useWritePdo()->whereIn('id', $ids)->orderBy('id')->lockForUpdate()->get()->all());
    }

    /**
     * Refuse a row under the lock in a connection that is not.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\Link>  $rows
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $locked
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged
     */
    private static function assertCovered(array $rows, array $locked): void
    {
        $ids = array_map(static fn (Connection $connection): string => $connection->id, $locked);

        foreach ($rows as $row) {

            if (!in_array($row->connection_id, $ids, true)) {
                throw LinkCandidatesChanged::retryWhole();
            }
        }
    }

    /**
     * Under the guard, lock the connections holding the identity's rows and the
     * rows, and make every change in those of another tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\LinkStorage  $storage
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $tenantId
     * @return int
     *
     * @throws \SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged
     */
    private function suspended(LinkStorage $storage, IdentityReference $identity, ?string $tenantId): int
    {
        $locked = self::lockedConnections(self::owned(self::rowsOf($identity)->get()->all(), $identity));
        $rows   = self::owned(self::rowsOf($identity)->orderBy('id')->lockForUpdate()->get()->all(), $identity);

        self::assertCovered($rows, $locked);

        $suspended = 0;

        foreach ($locked as $connection) {

            if ($connection->tenant_id === $tenantId) {
                continue;
            }

            $suspended += self::widenedIn($storage, $connection, array_values(array_filter($rows, static fn (Link $row): bool => $row->connection_id === $connection->id)));
        }

        return $suspended;
    }

    /**
     * Make every change of one locked connection; answer how many links this
     * suspended.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\LinkStorage  $storage
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  list<\SineMacula\Laravel\Sso\Models\Link>  $rows
     * @return int
     */
    private static function widenedIn(LinkStorage $storage, Connection $locked, array $rows): int
    {
        ReservationWithdrawal::ofRows($locked, $rows);

        $suspended = 0;

        foreach ($rows as $row) {

            if ($row->state === LinkState::RESERVED) {
                continue;
            }

            $identity = new IdentityReference($row->identity_type, $row->identity_id);

            if ($row->state === LinkState::ACTIVE) {
                $storage->suspend($row->id, $identity, $locked->id, $locked->tenant_id, $locked->protocol);
                $suspended++;
            }

            $storage->revokeSessions($row->id, $identity, $locked->id, $locked->tenant_id);
        }

        return $suspended;
    }
}
