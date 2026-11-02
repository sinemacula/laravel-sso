<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * What an application's principal mutation calls when a person comes to hold a
 * principal (SSO-8.8, `docs/guides/linking-by-domain.md`): checks at completion
 * and at redemption cannot see a principal added and removed between them, so
 * the change itself reports it, in its own transaction.
 *
 * `widened()` is given the identity and the tenant of the new principal, `null`
 * for a platform principal. For each connection of another tenant holding one
 * of the identity's links by a verified domain, in ascending id order:
 *
 * - the connection's row is locked, then the identity's links in it;
 * - an active link is suspended: stored, latched (`Links\LinkStore::suspend()`,
 *   which raises the connection's links version and reports `LinkSuspended`
 *   after commit), so removing the principal later never restores it;
 * - a live or expired reservation is deleted, raising the links version, so one
 *   reserved before the principal was added cannot activate once it is removed;
 * - the sessions established through each active or already suspended link are
 *   revoked through `Contracts\SessionRevocation`, in that same transaction,
 *   with `RevocationScope::identityLink()` and the reason `scope_widened`. A
 *   link that a resolution suspended earlier revoked nothing then, so it is
 *   revoked here, with no second event.
 *
 * A connection of the new principal's tenant is left alone: the principal is
 * inside it. Tenants are opaque, and compared exactly.
 *
 * The lock order: this is the first thing the principal-change transaction
 * does. The package's locks come before the application's guards in every path
 * (`docs/design/linking.md`), so the writer calls `widened()`, then takes its
 * principal guard, then writes the principal, then calls `assertSettled()`:
 *
 * ```php
 * DB::connection($storage)->transaction(function () use ($widening, $identity, $tenantId): void {
 *     $widening->widened($identity, $tenantId);
 *     // take the guard the principal scope contract documents; write the principal
 *     $widening->assertSettled($identity, $tenantId);
 * });
 * ```
 *
 * It takes connections in ascending id order and no enforcement guard, which
 * only ever comes before connections, so it cannot deadlock against a
 * completion or a redemption. Which connections hold the identity's links is
 * found by a plain read, since locking link rows before their connection would
 * break the order; each connection's rows are then read again under its lock.
 *
 * `assertSettled()` closes what that plain read leaves open: a reservation made
 * and a link activated between it and the application's guard, each of which
 * judged the principal scope before the new principal existed. Once the guard
 * is held no later judgement can miss the principal, so it reads the identity's
 * links once more, current, and a link or reservation `widened()` did not reach
 * is a `RuntimeException`, which rolls the change back: the application retries
 * its whole transaction, never a part of it, and `widened()` then finds it. The
 * read takes a shared lock on the link rows alone, since a plain read under
 * MySQL's `REPEATABLE READ` would answer from its snapshot. A redemption
 * holding such a row while it waits for the guard makes the database abort one
 * of the two, which is safe in the same way. Under PostgreSQL's
 * `REPEATABLE READ`, which cannot see a row inserted after its snapshot, the
 * change runs at `READ COMMITTED`, PostgreSQL's default.
 *
 * Only the package's link store can hold a link by a verified domain, so with
 * an alternative linker there is nothing here to suspend. Called with no
 * transaction open on the storage connection, each is a `LogicException`: a
 * suspension that commits apart from the change could leave one without the
 * other. A database error and a revocation's exception propagate and roll the
 * change back (SSO-11.4). It holds the store and the container, neither of
 * which keeps anything of one change for the next (SSO-11.2). Resolve it from
 * the container per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ScopeWidening
{
    /** @var list<string> The states of a row `widened()` still has to change. */
    private const array UNSETTLED = [LinkState::ACTIVE->value, LinkState::RESERVED->value];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkStore  $links
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Stores and reports each suspension. */
        private LinkStore $links,

        /** Resolves the revocation contract at each change. */
        private Container $container,
    ) {}

    /**
     * Suspend the identity's links by a verified domain in every connection of
     * another tenant than the new principal's, delete its reservations in them,
     * and revoke the sessions established through those links; answer how many
     * links this suspended.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $tenantId
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function widened(IdentityReference $identity, ?string $tenantId): int
    {
        self::assertInTransaction();

        $suspended = 0;

        foreach (self::connectionsOutside(self::rowsOf($identity)->get()->all(), $identity, $tenantId) as $connectionId) {
            $suspended += $this->widenedIn($connectionId, $identity);
        }

        return $suspended;
    }

    /**
     * Refuse the change when a link or a reservation `widened()` did not reach
     * has appeared, once the application holds its principal guard.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $tenantId
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     */
    public function assertSettled(IdentityReference $identity, ?string $tenantId): void
    {
        self::assertInTransaction();

        $rows = self::rowsOf($identity)->whereIn('state', self::UNSETTLED)->sharedLock()->get()->all();

        if (self::connectionsOutside($rows, $identity, $tenantId) !== []) {
            throw self::unsettled();
        }
    }

    /**
     * What a change that must be retried whole is refused with.
     *
     * @return \RuntimeException
     */
    private static function unsettled(): \RuntimeException
    {
        return new \RuntimeException('An identity\'s links changed while its scope widened; retry the whole transaction.');
    }

    /**
     * Refuse a call with no transaction open on the storage connection.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertInTransaction(): void
    {
        if (DB::connection(StorageConnection::name())->transactionLevel() === 0) {
            throw new \LogicException('A widened scope is reported inside the transaction that changes the person\'s principals, on the storage connection (decision D5).');
        }
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
     * The ids of the connections holding the identity's rows, of another tenant
     * than the one given, in ascending order. A connection's tenant never
     * changes, so a plain read of it is enough.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\Link>  $rows
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $tenantId
     * @return array<int, string>
     */
    private static function connectionsOutside(array $rows, IdentityReference $identity, ?string $tenantId): array
    {
        $held = array_map(static fn (Link $row): string => $row->connection_id, array_filter($rows, static fn (Link $row): bool => self::isOwnedBy($row, $identity)));

        if ($held === []) {
            return [];
        }

        $connections = Connection::query()->useWritePdo()->whereKey($held)->orderBy('id')->get(['id', 'tenant_id'])->all();
        $outside     = array_filter($connections, static fn (Connection $connection): bool => $connection->tenant_id !== $tenantId);

        return array_map(static fn (Connection $connection): string => $connection->id, $outside);
    }

    /**
     * Whether the row is the identity's, byte for byte, whatever the collation.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $row
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     */
    private static function isOwnedBy(Link $row, IdentityReference $identity): bool
    {
        return $row->identity_type === $identity->type && $row->identity_id === $identity->id;
    }

    /**
     * Under the connection's lock, then its rows', make every change of one
     * connection; answer how many links this suspended.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function widenedIn(string $connectionId, IdentityReference $identity): int
    {
        $locked = Connection::query()->useWritePdo()->whereKey($connectionId)->lockForUpdate()->first();

        if ($locked === null) {
            return 0;
        }

        $found = self::rowsOf($identity)->where('connection_id', $connectionId)->lockForUpdate()->get()->all();
        $rows  = array_filter($found, static fn (Link $row): bool => self::isOwnedBy($row, $identity));

        ReservationWithdrawal::ofRows($locked, $rows);

        $suspended = 0;

        foreach ($rows as $row) {

            if ($row->state === LinkState::ACTIVE) {
                $this->links->suspend($row, $locked->tenant_id, $locked->protocol);
                $suspended++;
            }

            if ($row->state !== LinkState::SUSPENDED) {
                continue;
            }

            $this->revoke($locked, $identity, $row);
        }

        return $suspended;
    }

    /**
     * Revoke the identity's sessions established through the link.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Models\Link  $row
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function revoke(Connection $locked, IdentityReference $identity, Link $row): void
    {
        $this->container->make(SessionRevocation::class)->revoke(RevocationScope::identityLink($locked->tenant_id, $locked->id, $identity, $row->id));
    }
}
