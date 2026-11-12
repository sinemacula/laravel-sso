<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
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
use SineMacula\Laravel\Sso\Identities\Caller;
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
 * The package's `Contracts\LinkStorage` over the links table, and the one place
 * a link is created.
 *
 * A caller in its own transaction locks the result's connection before
 * `resolve()`, so a link is never locked before its connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkStore implements LinkStorage
{
    /** @var int How often a link's last use is stamped at most, in seconds. */
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
     * Count the identity's held links in the connection by a locking read.
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
     * What the result resolves to within the connection it completed through.
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
     * Clear the link's suspension and domain provenance for good, under the
     * redemption's locks.
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
     * Latch the locked link's suspension and report it.
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
     * Revoke the sessions established through the locked link, in the caller's
     * transaction.
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
     * Link the subject to the identity unless it is linked already or the
     * identity is at its limit.
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
        ?Caller $caller = null,
        ?string $application = null,
        ?Purpose $purpose = null,
        ?RequestReference $reference = null,
    ): LinkCreation {
        $report = function (Connection $locked) use ($identity, $origin, $client, $caller, $application, $purpose, $reference): void {
            $this->events->created($locked, $identity, $origin, $client, $caller, $application, $purpose, $reference);
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
     * The subject's row in the connection by a locking read, matched byte for
     * byte as well as by key, or `null`.
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
     * What the active row resolves to, judging a domain-made link's principal
     * scope first.
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
     * Suspend the link for good and revoke its sessions, unless another caller
     * latched it first under the same locks.
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
     * Stamp the link's last use, at most once per
     * `LAST_USED_RESOLUTION_SECONDS`.
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
     * Raise the links version, so a stale PostgreSQL snapshot fails to
     * serialise rather than miss the link.
     *
     * @param  string  $connectionId
     * @return void
     */
    private static function raiseLinksVersion(string $connectionId): void
    {
        Connection::query()->useWritePdo()->whereKey($connectionId)->increment('links_version');
    }

    /**
     * The connection's row, read again locked for update.
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
     * The bound link limit for the identity in the connection.
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
     * Insert the active link in a savepoint; `null` when the subject's unique
     * index refuses it.
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
