<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * The package's link store (SSO-8.2 to SSO-8.4, SSO-1.5): the
 * `Contracts\LinkStorage` over the links table, and the one place a link is
 * created.
 *
 * It is not the default: `Links\NoLinks` is, and links nothing. The application
 * binds this store as `Contracts\Linker`, or an adapter does, answering the
 * link questions of the application's authentication from it too.
 *
 * `resolve()` finds the row of the result's connection whose `subject_key` is
 * `LinkSubject::of($result)->key()`, by a locking read on the write connection
 * (SSO-11.3), and compares the connection, issuer, format and subject again in
 * PHP, byte for byte, so neither a collation nor a forged key can match another
 * subject (SSO-6.9). A result reaches only the links of the connection it
 * completed through: another connection with the same issuer and subject
 * resolves nothing. It answers a `LinkResolution`:
 *
 * - no row, or a reservation expired, is `absent`;
 * - a live reservation is `reserved`, and a row suspended is `suspended`;
 * - an active link is `linked`, with `last_used_at` stamped from the clock by
 *   one conditional update, at most once a minute, for a `sign_in` result
 *   alone, since a `link` or a `reauthenticate` is no sign-in. A link that
 *   stands on a verified domain asks `Contracts\PrincipalScope` first, for its
 *   identity and the result's tenant:
 *   - `within_tenant` goes on;
 *   - `outside_tenant` stores the suspension, latched (`suspended_at`, the
 *     connection's links version raised), and revokes the sessions established
 *     through the link, in one transaction (a savepoint inside the caller's),
 *     in the established lock order: the link's connection is locked, then the
 *     link read again by a locking read, and only a link still active by a
 *     verified domain is suspended, revoked and reported, once. The answer is
 *     `suspended`. The principal's change was the place to revoke them; this
 *     repairs what it missed, and asking twice is safe. Removing the principal
 *     later never restores the link; only `confirm()`, from a confirming
 *     `link`, does (SSO-8.8). A principal added and removed between resolutions
 *     is what `Linking\ScopeWidening` catches;
 *   - `unknown` is `scope_unknown`: this attempt is refused, and nothing is
 *     stored, suspended or revoked, since uncertainty asserts no widening. An
 *     implementation that cannot reach its store throws instead.
 *
 * A caller inside a transaction of its own locks the result's connection before
 * it resolves, as the package's completion and redemptions do, so the link is
 * never locked before its connection; with none open, `resolve()` keeps that
 * order itself.
 *
 * `create()` makes an active link, in one transaction on the storage connection
 * (a savepoint inside the caller's), in a fixed order: the connection's row is
 * read again locked, which serialises every creation in the connection; the
 * identity's links in it are counted by a locking read, active and suspended
 * ones and reserved ones whose reservation has not expired; the link limit
 * contract, resolved from the container at that moment, is asked, and an answer
 * below one is a `LogicException` naming the binding; at the limit it is
 * `link_limit_reached`; an expired reservation of the subject is deleted, since
 * it holds nothing; the link is inserted through the model in a savepoint, and
 * the unique index on connection and key refusing it is
 * `subject_already_linked`; the connection's links version is raised by one, so
 * a link's insert also writes the connection's row (a PostgreSQL
 * `REPEATABLE READ` transaction that locks the row after the creation commits
 * then fails to serialise rather than miss the link); and `LinkCreated` is
 * reported after commit. A missing connection is a `LogicException`; any other
 * error propagates (SSO-11.4).
 *
 * `confirm()` clears a link's suspension and verified domain provenance for
 * good, under the connection's lock, raising its links version and reporting
 * `LinkConfirmed` (SSO-8.8, SSO-5.11).
 *
 * Every call that can report takes the client it is made for
 * (`Http\ClientContext`), whose IP address and user agent the event carries. It
 * holds the connection lookup, the clock, the reporter and the container, none
 * of which keeps anything of one request for the next (SSO-11.2).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkStore implements LinkStorage
{
    /** @var int How long, in seconds, a link's last use stands before a resolution stamps it again. */
    public const int LAST_USED_RESOLUTION_SECONDS = 60;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $connections
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Links\LinkEvents  $events
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Locks the connection a link is created through. */
        private ConnectionFinder $connections,

        /** The clock reservations and last use are judged against. */
        private Clock $clock,

        /** Reports each link created, after commit. */
        private LinkEvents $events,

        /** Resolves the link limit contract at each creation. */
        private Container $container,
    ) {}

    /**
     * The number of links the identity holds in the connection, by a locking
     * read: active and suspended ones, and reserved ones that have not expired.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return int
     */
    #[\Override]
    public function holdings(string $connectionId, IdentityReference $identity): int
    {
        return LinkHoldings::count($connectionId, $identity, $this->clock->now());
    }

    /**
     * What the result's connection, issuer, format and subject resolve to.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Links\LinkResolution
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    #[\Override]
    public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
    {
        $link = self::rowOf($result->connectionId, LinkSubject::of($result));

        if ($link === null) {
            return LinkResolution::absent();
        }

        return match ($link->state) {
            LinkState::RESERVED  => $this->isLiveReservation($link) ? LinkResolution::reserved() : LinkResolution::absent(),
            LinkState::SUSPENDED => LinkResolution::suspended(self::identityOf($link), $link->id),
            LinkState::ACTIVE    => $this->resolvedActive($link, $result, $client),
        };
    }

    /**
     * Clear the link's suspension and verified domain provenance for good, once
     * the person confirmed it through the `link` purpose, under the locks of
     * the redemption, unless it is already neither.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $locked
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function confirm(SsoConnection $locked, string $linkId, ClientContext $client, ?string $application = null, ?RequestReference $reference = null): void
    {
        $link = Link::query()->useWritePdo()->whereKey($linkId)->where('connection_id', $locked->getConnectionId())->lockForUpdate()->first();

        if ($link === null || !$link->domain_provenance) {
            return;
        }

        $link->forceFill(['state' => LinkState::ACTIVE, 'suspended_at' => null, 'provenance' => LinkOrigin::LINK_PURPOSE])->save();

        self::raiseLinksVersion($locked->getConnectionId());

        $this->events->confirmed($locked, self::identityOf($link), $client, $application, $reference);
    }

    /**
     * Store the locked link's suspension, latched, raise the connection's links
     * version and report it.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  string  $protocol
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function suspend(string $linkId, IdentityReference $identity, string $connectionId, string $tenantId, string $protocol, ClientContext $client): void
    {
        $query = Link::query()->useWritePdo();
        $now   = UtcDateTime::format($query->getModel(), $this->clock->now());

        $query->whereKey($linkId)->update(['state' => LinkState::SUSPENDED->value, 'suspended_at' => $now, 'updated_at' => $now]);

        self::raiseLinksVersion($connectionId);

        $this->events->suspended($connectionId, $tenantId, $protocol, $identity, $client);
    }

    /**
     * Revoke the sessions established through the locked link, through the
     * bound revocation, resolved at that moment, in the caller's transaction.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function revokeSessions(string $linkId, IdentityReference $identity, string $connectionId, string $tenantId): void
    {
        $this->container->make(SessionRevocation::class)->revoke(RevocationScope::identityLink($tenantId, $connectionId, $identity, $linkId));
    }

    /**
     * The one writer of a reserved row.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkReservations
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function reservations(): LinkReservations
    {
        return $this->container->make(LinkReservations::class);
    }

    /**
     * Make an active link of the subject, through the connection, to the
     * identity, unless the subject is linked already or the identity holds as
     * many links in the connection as it may.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return \SineMacula\Laravel\Sso\Links\LinkCreation
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     *
     * @SuppressWarnings("php:S107")
     */
    #[\Override]
    public function create(
        SsoConnection $connection,
        LinkSubject $subject,
        IdentityReference $identity,
        LinkOrigin $origin,
        ClientContext $client,
        ?ActingIdentity $actor = null,
        ?string $application = null,
        ?Purpose $purpose = null,
        ?RequestReference $reference = null,
    ): LinkCreation {
        $report = function (Connection $locked) use ($identity, $origin, $client, $actor, $application, $purpose, $reference): void {
            $this->events->created($locked, $identity, $origin, $client, $actor, $application, $purpose, $reference);
        };

        return DB::connection(StorageConnection::name())->transaction(function () use ($connection, $subject, $identity, $origin, $report): LinkCreation {

            $locked = $this->lockedConnection($connection);

            if ($this->holdings($locked->id, $identity) >= $this->limit($identity, $locked)) {
                return LinkCreation::linkLimitReached();
            }

            $this->reservations()->replaceExpired($locked, $subject);

            $link = self::inserted($locked, $subject, $identity, $origin);

            if ($link === null) {
                return LinkCreation::subjectAlreadyLinked();
            }

            self::raiseLinksVersion($locked->id);

            $report($locked);

            return LinkCreation::created(LinkSummary::of($link, $locked));
        });
    }

    /**
     * The row of the subject in the connection, of any state, by a locking read
     * on the write connection, or `null` when there is none. A row is the
     * subject's only when what it holds matches byte for byte as well as its
     * key, whatever the collation.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @return ?\SineMacula\Laravel\Sso\Models\Link
     *
     * @throws \InvalidArgumentException
     */
    private static function rowOf(string $connectionId, LinkSubject $subject): ?Link
    {
        $link = Link::query()
            ->useWritePdo()
            ->where('connection_id', $connectionId)
            ->where('subject_key', $subject->key())
            ->lockForUpdate()
            ->first();

        return $link !== null && self::isFor($link, $connectionId, $subject) ? $link : null;
    }

    /**
     * Whether the link found is the subject's in the connection, byte for byte.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private static function isFor(Link $link, string $connectionId, LinkSubject $subject): bool
    {
        $stored = new LinkSubject($link->issuer, $link->subject, $link->name_id_format);

        return $link->connection_id === $connectionId && $stored->is($subject);
    }

    /**
     * The identity the row holds.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     *
     * @throws \InvalidArgumentException
     */
    private static function identityOf(Link $link): IdentityReference
    {
        return new IdentityReference($link->identity_type, $link->identity_id);
    }

    /**
     * Whether the reserved row's reservation expires after now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @return bool
     */
    private function isLiveReservation(Link $link): bool
    {
        return $link->reservation_expires_at?->isAfter($this->clock->now()) ?? false;
    }

    /**
     * What the active row resolves to: its identity and its provenance, once a
     * sign-in's use is stamped, unless it stands on a verified domain and its
     * identity's principals are not known to be within the tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Links\LinkResolution
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    private function resolvedActive(Link $link, VerifiedResult $result, ClientContext $client): LinkResolution
    {
        $identity = self::identityOf($link);
        $verdict  = $link->domain_provenance ? $this->container->make(PrincipalScope::class)->judge($identity, $result->tenantId) : ScopeVerdict::WITHIN_TENANT;

        if ($verdict === ScopeVerdict::OUTSIDE_TENANT) {
            return $this->latched($link, $result, $identity, $client);
        }

        if ($verdict === ScopeVerdict::UNKNOWN) {
            return LinkResolution::scopeUnknown($identity, $link->id);
        }

        if ($result->purpose === Purpose::SIGN_IN) {
            $this->stampLastUsed($link);
        }

        return LinkResolution::linked($identity, $link->id, $link->provenance);
    }

    /**
     * Suspend the link for good, and revoke the sessions established through
     * it, in one transaction (a savepoint inside the caller's): the link's
     * connection is locked first, then the link is read again by a locking
     * read, and only a link still active by a verified domain is suspended and
     * reported; anything else is resolved again as it is now, under those
     * locks, so a latch another caller made first is never made twice.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Links\LinkResolution
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function latched(Link $link, VerifiedResult $result, IdentityReference $identity, ClientContext $client): LinkResolution
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($link, $result, $identity, $client): LinkResolution {

            $this->connections->findForUpdate($result->tenantId, $link->connection_id);

            $row = Link::query()->useWritePdo()->whereKey($link->id)->lockForUpdate()->first();

            if ($row?->state !== LinkState::ACTIVE || !$row->domain_provenance) {
                return $this->resolve($result, $client);
            }

            $this->suspend($link->id, $identity, $link->connection_id, $result->tenantId, $result->protocol, $client);
            $this->revokeSessions($link->id, $identity, $link->connection_id, $result->tenantId);

            return LinkResolution::suspended($identity, $link->id);
        });
    }

    /**
     * Stamp the link's last use with the clock's now, in one update that
     * changes the row only when it was never used or last used at least
     * `LAST_USED_RESOLUTION_SECONDS` ago.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @return void
     */
    private function stampLastUsed(Link $link): void
    {
        $now       = $this->clock->now();
        $threshold = UtcDateTime::format($link, $now->subSeconds(self::LAST_USED_RESOLUTION_SECONDS));

        Link::query()
            ->useWritePdo()
            ->whereKey($link->id)
            ->where(static function (Builder $query) use ($threshold): void {
                $query->whereNull('last_used_at')->orWhere('last_used_at', '<=', $threshold);
            })
            ->update(['last_used_at' => UtcDateTime::format($link, $now)]);
    }

    /**
     * Raise the locked connection's links version by one, so the insert also
     * writes the connection's row: a PostgreSQL `REPEATABLE READ` transaction
     * that locks the row after this one commits fails to serialise, rather than
     * go on from a snapshot without the link (`SubjectMigration`).
     *
     * @param  string  $connectionId
     * @return void
     */
    private static function raiseLinksVersion(string $connectionId): void
    {
        Connection::query()->useWritePdo()->whereKey($connectionId)->increment('links_version');
    }

    /**
     * The connection's row, read again locked for update until the transaction
     * ends.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \LogicException
     */
    private function lockedConnection(SsoConnection $connection): Connection
    {
        return $this->connections->findForUpdate($connection->getTenantId(), $connection->getConnectionId())
            ?? throw new \LogicException(sprintf('No connection [%s] exists to link through.', $connection->getConnectionId()));
    }

    /**
     * The most links the identity may hold in the connection, as the bound link
     * limit contract answers.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function limit(IdentityReference $identity, Connection $connection): int
    {
        return LinkHoldings::limitOf($this->container->make(LinkLimit::class), $identity, $connection);
    }

    /**
     * Insert the active link through the model in a transaction of its own (a
     * savepoint inside the creation's), or answer `null` when the unique index
     * on the connection and the subject's key refuses it. Any other error
     * propagates.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @return ?\SineMacula\Laravel\Sso\Models\Link
     *
     * @throws \Throwable
     */
    private static function inserted(Connection $connection, LinkSubject $subject, IdentityReference $identity, LinkOrigin $origin): ?Link
    {
        $link = new Link;

        $link->forceFill([
            'connection_id'  => $connection->id,
            'issuer'         => $subject->issuer,
            'name_id_format' => $subject->nameIdFormat,
            'subject'        => $subject->subject,
            'subject_key'    => $subject->key(),
            'identity_type'  => $identity->type,
            'identity_id'    => $identity->id,
            'state'          => LinkState::ACTIVE,
            'provenance'     => $origin,
        ]);

        try {
            DB::connection(StorageConnection::name())->transaction(static fn (): bool => $link->save());
        } catch (UniqueConstraintViolationException) {
            return null;
        }

        return $link;
    }
}
