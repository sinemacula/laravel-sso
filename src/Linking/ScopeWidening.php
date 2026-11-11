<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Http\ClientContext;
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
 * person's principals, on the storage connection, given the identities whose
 * principals it changes (a list, so one change to several takes their locks in
 * one order), the tenant of the new principal, `null` for a platform principal,
 * and the client the change is made for (`Http\ClientContext`, which each
 * `LinkSuspended` carries: `new ClientContext(null, null)` from a console
 * command or a job); then takes the guard `Contracts\PrincipalScope` documents,
 * writes the principal, and commits:
 *
 * ```php DB::connection($storage)->transaction(function () use ($widening,
 * $identity, $tenantId, $client): void {
 *     $widening->widened([$identity], $tenantId, $client);
 *     // take the guard the principal scope contract documents; write the principal
 * });
 * ```
 *
 * It takes each identity's guard first (`Linking\IdentityLock`), once, in
 * ascending order of `IdentityLock::digest()`, and holds them until that
 * transaction ends. A reservation, an activation and a confirmation of an
 * identity take the same guard first, so each runs wholly before this change,
 * and is found here, or wholly after it, and sees the principal written.
 * Nothing can slip in between, whatever the isolation level. For each
 * connection of another tenant holding one of the identities' links by a
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
 * The lock order is the package's: identity guards, connections ascending,
 * links, then the application's guards. Which connections hold the identities'
 * rows is found by a plain read once every guard is held, since locking link
 * rows before their connections would break that order; those connections, for
 * every identity together, are locked in one statement, and the rows are then
 * read again by a locking read. A row in a connection that was not locked,
 * which only a transaction with an older snapshot can come to, is
 * `Exceptions\LinkCandidatesChanged` before anything is changed, and the
 * application retries its whole transaction. Under PostgreSQL's
 * `REPEATABLE READ` such a transaction fails to serialise at the guard instead.
 *
 * A linker not backed by `Contracts\LinkStorage` holds no such link, so with
 * one bound only the guards are taken, and an empty list takes nothing and
 * answers 0. Called with no transaction open on the storage connection it is a
 * `LogicException`: a suspension that commits apart from the change could leave
 * one without the other. A database error and a revocation's exception
 * propagate and roll the change back (SSO-11.4). It holds the binding and the
 * lock, neither of which keeps anything of one change for the next (SSO-11.2).
 * Resolve it from the container per request.
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

        /** Holds each identity's linking changes apart from this one. */
        private IdentityLock $identities,
    ) {}

    /**
     * Take the identities' guards; suspend their links by a verified domain in
     * every connection of another tenant than the new principal's, delete their
     * reservations in them, and revoke the sessions established through those
     * links; answer how many links this suspended.
     *
     * @param  list<\SineMacula\Laravel\Sso\Identities\IdentityReference>  $identities
     * @param  ?string  $tenantId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return int
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged
     */
    public function widened(array $identities, ?string $tenantId, ClientContext $client): int
    {
        if ($identities === []) {
            return 0;
        }

        if (DB::connection(StorageConnection::name())->transactionLevel() === 0) {
            throw new \LogicException('A widened scope is reported inside the transaction that changes the person\'s principals, on the storage connection (decision D5).');
        }

        $guarded = self::byDigest($identities);

        foreach ($guarded as $identity) {
            $this->identities->acquire($identity);
        }

        $storage = $this->storage->find();

        return $storage === null ? 0 : $this->suspended($storage, $guarded, $tenantId, $client);
    }

    /**
     * The identities once each, keyed by and in ascending order of their
     * guard's digest.
     *
     * @param  list<\SineMacula\Laravel\Sso\Identities\IdentityReference>  $identities
     * @return array<string, \SineMacula\Laravel\Sso\Identities\IdentityReference>
     */
    private static function byDigest(array $identities): array
    {
        $guarded = [];

        foreach ($identities as $identity) {
            $guarded[IdentityLock::digest($identity)] = $identity;
        }

        ksort($guarded, SORT_STRING);

        return $guarded;
    }

    /**
     * The query of the identities' links by a verified domain, on the write
     * connection, whatever the state.
     *
     * @param  array<string, \SineMacula\Laravel\Sso\Identities\IdentityReference>  $identities
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Sso\Models\Link>
     */
    private static function rowsOf(array $identities): Builder
    {
        return Link::query()->useWritePdo()
            ->where(static function (Builder $query) use ($identities): void {

                foreach ($identities as $identity) {
                    $query->orWhere(static fn (Builder $held): Builder => $held
                        ->where('identity_type', $identity->type)
                        ->where('identity_id', $identity->id));
                }
            })
            ->where('provenance', LinkOrigin::VERIFIED_DOMAIN->value);
    }

    /**
     * The rows that are one of the identities', byte for byte, whatever the
     * collation.
     *
     * @param  array<int, \SineMacula\Laravel\Sso\Models\Link>  $rows
     * @param  array<string, \SineMacula\Laravel\Sso\Identities\IdentityReference>  $identities
     * @return list<\SineMacula\Laravel\Sso\Models\Link>
     */
    private static function owned(array $rows, array $identities): array
    {
        $isOwned = static fn (Link $row): bool => isset($identities[IdentityLock::digest(new IdentityReference($row->identity_type, $row->identity_id))]);

        return array_values(array_filter($rows, $isOwned));
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
     * Under the guards, lock the connections holding the identities' rows and
     * the rows, and make every change in those of another tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\LinkStorage  $storage
     * @param  array<string, \SineMacula\Laravel\Sso\Identities\IdentityReference>  $identities
     * @param  ?string  $tenantId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return int
     *
     * @throws \SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged
     */
    private function suspended(LinkStorage $storage, array $identities, ?string $tenantId, ClientContext $client): int
    {
        $locked = self::lockedConnections(self::owned(self::rowsOf($identities)->get()->all(), $identities));
        $rows   = self::owned(self::rowsOf($identities)->orderBy('id')->lockForUpdate()->get()->all(), $identities);

        self::assertCovered($rows, $locked);

        $suspended = 0;

        foreach ($locked as $connection) {

            if ($connection->tenant_id === $tenantId) {
                continue;
            }

            $held = array_values(array_filter($rows, static fn (Link $row): bool => $row->connection_id === $connection->id));
            $suspended += self::widenedIn($storage, $connection, $held, $client);
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
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return int
     */
    private static function widenedIn(LinkStorage $storage, Connection $locked, array $rows, ClientContext $client): int
    {
        ReservationWithdrawal::ofRows($locked, $rows);

        $suspended = 0;

        foreach ($rows as $row) {

            if ($row->state === LinkState::RESERVED) {
                continue;
            }

            $identity = new IdentityReference($row->identity_type, $row->identity_id);

            if ($row->state === LinkState::ACTIVE) {
                $storage->suspend($row->id, $identity, $locked->id, $locked->tenant_id, $locked->protocol, $client);
                $suspended++;
            }

            $storage->revokeSessions($row->id, $identity, $locked->id, $locked->tenant_id);
        }

        return $suspended;
    }
}
