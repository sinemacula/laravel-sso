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
 * Suspends an identity's domain-made links in other tenants when it gains a
 * principal, which no later check could see.
 *
 * Call first in the transaction that writes the principal, on the storage
 * connection, before the application's own guard.
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
     * Guard the identities, then suspend, withdraw and revoke in other tenants'
     * connections; answer how many links were suspended.
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
            throw new \LogicException('A widened scope is reported inside the transaction that changes the person\'s principals, on the storage connection.');
        }

        $guarded = self::byDigest($identities);

        foreach ($guarded as $identity) {
            $this->identities->acquire($identity);
        }

        $storage = $this->storage->find();

        return $storage === null ? 0 : $this->suspended($storage, $guarded, $tenantId, $client);
    }

    /**
     * The identities once each, keyed and sorted by their guard's digest.
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
     * The identities' domain-made links, whatever the state.
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
     * The rows that are one of the identities', byte for byte whatever the
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
     * Lock the connections holding the rows in one statement, in ascending id
     * order.
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
     * Refuse a locked row in an unlocked connection; the caller retries its
     * whole transaction.
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
     * Find connections by a plain read, lock them then the rows, and change
     * those of other tenants.
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
