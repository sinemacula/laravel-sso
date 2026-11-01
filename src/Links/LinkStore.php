<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The package's link store (SSO-8.2 to SSO-8.4, SSO-1.5): the `Linker` over the
 * links table, and the one place a link is created.
 *
 * It is not the default: `Links\NoLinks` is, and links nothing. The application
 * binds this store as `Contracts\Linker`, or `laravel-iam` does, which under it
 * also answers `laravel-authentication`'s link contract.
 *
 * `resolve()` finds the active link of the result's connection whose
 * `subject_key` is `LinkSubject::of($result)->key()`, by a locking read on the
 * write connection (SSO-11.3), and compares the connection, issuer, format and
 * subject again in PHP, byte for byte, so neither a collation nor a forged key
 * can match another subject (SSO-6.9). A result reaches only the links of the
 * connection it completed through: another connection with the same issuer and
 * subject resolves nothing. A reserved link resolves nothing. A link it
 * resolves has `last_used_at` stamped from the clock by one conditional update,
 * at most once a minute.
 *
 * `create()` makes an active link, in one transaction on the storage connection
 * (a savepoint inside the caller's), in a fixed order: the connection's row is
 * read again locked, which serialises every creation in the connection; the
 * identity's links in it are counted by a locking read, active ones and
 * reserved ones whose reservation has not expired; the link limit contract,
 * resolved from the container at that moment, is asked, and an answer below one
 * is a `LogicException` naming the binding; at the limit it is
 * `link_limit_reached`; the link is inserted through the model in a savepoint,
 * and the unique index on connection and key refusing it is
 * `subject_already_linked`; and `LinkCreated` is reported after commit. A
 * missing connection is a `LogicException`; any other error propagates
 * (SSO-11.4).
 *
 * It holds the connection lookup, the clock, the reporter and the container,
 * none of which keeps anything of one request for the next (SSO-11.2).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkStore implements Linker
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
     * The identity the result's connection, issuer, format and subject are
     * linked to by an active link, or `null` when there is none.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return ?\SineMacula\Laravel\Sso\Identities\IdentityReference
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function resolve(VerifiedResult $result): ?IdentityReference
    {
        $link = self::activeLink($result->connectionId, LinkSubject::of($result));

        if ($link === null || $this->isSuspended($link)) {
            return null;
        }

        $this->stampLastUsed($link);

        return new IdentityReference($link->identity_type, $link->identity_id);
    }

    /**
     * Make an active link of the subject, through the connection, to the
     * identity, unless the subject is linked already or the identity holds as
     * many links in the connection as it may.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
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
    public function create(
        Connection $connection,
        LinkSubject $subject,
        IdentityReference $identity,
        LinkOrigin $origin,
        ?ActingIdentity $actor = null,
        ?string $application = null,
        ?Purpose $purpose = null,
        ?RequestReference $reference = null,
    ): LinkCreation {
        $report = function (Connection $locked) use ($identity, $origin, $actor, $application, $purpose, $reference): void {
            $this->events->created($locked, $identity, $origin, $actor, $application, $purpose, $reference);
        };

        return DB::connection(StorageConnection::name())->transaction(function () use ($connection, $subject, $identity, $origin, $report): LinkCreation {

            $locked = $this->lockedConnection($connection);

            if ($this->heldLinks($locked, $identity) >= $this->limit($identity, $locked)) {
                return LinkCreation::linkLimitReached();
            }

            $link = self::inserted($locked, $subject, $identity, $origin);

            if ($link === null) {
                return LinkCreation::subjectAlreadyLinked();
            }

            $report($locked);

            return LinkCreation::created(LinkSummary::of($link, $locked));
        });
    }

    /**
     * The active link of the subject in the connection, by a locking read on
     * the write connection, or `null` when there is none. A row is the
     * subject's only when what it holds matches byte for byte as well as its
     * key, whatever the collation.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @return ?\SineMacula\Laravel\Sso\Models\Link
     *
     * @throws \InvalidArgumentException
     */
    private static function activeLink(string $connectionId, LinkSubject $subject): ?Link
    {
        $link = Link::query()
            ->useWritePdo()
            ->where('connection_id', $connectionId)
            ->where('subject_key', $subject->key())
            ->where('state', LinkState::ACTIVE->value)
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
     * Whether the link's verified domain provenance is suspended, so it
     * resolves nothing (SSO-8.8).
     *
     * This is the seam of the provenance rule linking by a verified domain
     * adds: a link made by a verified domain, and not since confirmed through
     * the `link` purpose, resolves nothing whenever its identity holds a
     * principal outside the connection's tenant. Until that rule is built, no
     * link is suspended, and a link with `domain_provenance` resolves like any
     * other.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @return bool
     */
    private function isSuspended(Link $link): bool
    {
        unset($link);

        return false;
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
     * The connection's row, read again locked for update until the transaction
     * ends.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \LogicException
     */
    private function lockedConnection(Connection $connection): Connection
    {
        return $this->connections->findForUpdate($connection->tenant_id, $connection->id)
            ?? throw new \LogicException(sprintf('No connection [%s] exists to link through.', $connection->id));
    }

    /**
     * How many links the identity holds in the connection, by a locking read:
     * active ones, and reserved ones whose reservation expires after now. The
     * identity is compared byte for byte, whatever the collation.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return int
     */
    private function heldLinks(Connection $connection, IdentityReference $identity): int
    {
        $now = $this->clock->now();

        $links = Link::query()
            ->useWritePdo()
            ->where('identity_type', $identity->type)
            ->where('identity_id', $identity->id)
            ->where('connection_id', $connection->id)
            ->lockForUpdate()
            ->get()
            ->all();

        $held = array_filter($links, static fn (Link $link): bool => self::isOwnedBy($link, $identity) && self::isHeld($link, $now));

        return count($held);
    }

    /**
     * Whether the link is the identity's, byte for byte.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     */
    private static function isOwnedBy(Link $link, IdentityReference $identity): bool
    {
        return $link->identity_type === $identity->type && $link->identity_id === $identity->id;
    }

    /**
     * Whether the link counts toward the limit: active, or reserved until a
     * moment after now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    private static function isHeld(Link $link, CarbonImmutable $now): bool
    {
        if ($link->state === LinkState::ACTIVE) {
            return true;
        }

        return $link->reservation_expires_at?->isAfter($now) ?? false;
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
     */
    private function limit(IdentityReference $identity, Connection $connection): int
    {
        $binding = $this->container->make(LinkLimit::class);

        return self::assertLimit($binding, $binding->maxLinks($identity, $connection));
    }

    /**
     * The limit the binding answered, refused when it is below one.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\LinkLimit  $binding
     * @param  int  $limit
     * @return int
     *
     * @throws \LogicException
     */
    private static function assertLimit(LinkLimit $binding, int $limit): int
    {
        if ($limit < 1) {
            throw new \LogicException(sprintf('The link limit [%s] answered %d; a link limit is at least one.', $binding::class, $limit));
        }

        return $limit;
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
            'connection_id'     => $connection->id,
            'issuer'            => $subject->issuer,
            'name_id_format'    => $subject->nameIdFormat,
            'subject'           => $subject->subject,
            'subject_key'       => $subject->key(),
            'identity_type'     => $identity->type,
            'identity_id'       => $identity->id,
            'state'             => LinkState::ACTIVE,
            'domain_provenance' => $origin === LinkOrigin::VERIFIED_DOMAIN,
        ]);

        try {
            DB::connection(StorageConnection::name())->transaction(static fn (): bool => $link->save());
        } catch (UniqueConstraintViolationException) {
            return null;
        }

        return $link;
    }
}
