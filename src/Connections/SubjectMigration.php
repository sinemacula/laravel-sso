<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkCreationStatus;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkEvents;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * The explicit migration helper (SSO-2.13): the one way to change a setting
 * that may alter what a connection's existing subjects mean (one the protocol's
 * `subjectNames()` lists) while the connection has links, which
 * `ConnectionService::update()` refuses with `connection_has_links`. It makes
 * the change and, in the same transaction, relinks each link the caller maps to
 * its subject under the new meaning and removes each link the caller lists.
 *
 * `migrate()` takes the change as `update()` does, and an exhaustive
 * disposition of the connection's links: the relinks, each link id mapped to a
 * list of its new subject, then optionally its new SAML `NameID` format and its
 * new issuer (the format `null`, or left out, for none, and the issuer, when
 * `null` or left out, the link's own); and the removals, a list of link ids.
 * Every link the connection has when the migration runs must be in exactly one
 * of the two, so a link created after the caller prepared the call is never
 * removed or kept by accident. It goes in one order, and a refusal writes,
 * revokes and reports nothing:
 *
 * 1. In one transaction on the storage connection (a savepoint inside the
 *    caller's), the connection is read locked (`connection_not_found` when the
 *    tenant has no such connection, `protocol_unavailable` when its protocol is
 *    not), and then its links, locked, in id order.
 * 2. The disposition is judged against the locked links: a link in neither the
 *    relinks nor the removals, an id in both, or an id (or a removal that is
 *    not a string) that is not one of the connection's links is
 *    `links_unaccounted`, with nothing changed. Every link's creation raises
 *    the connection's `links_version` under the same lock, so on PostgreSQL
 *    under `REPEATABLE READ`, a migration whose snapshot predates a link fails
 *    to serialise when it locks the connection (SQLSTATE 40001, propagated)
 *    rather than go on without the link.
 * 3. The change is validated as `update()` validates one, and the relinks with
 *    it, each violation at `relinks.<id>`: `not_allowed` for a reserved link
 *    (only an active one is relinked; a reserved one may be removed),
 *    `invalid_type` for anything but a list of one to three strings (the format
 *    and issuer possibly `null`), and `invalid_format` for a subject, issuer or
 *    format of the wrong length; any violation is `invalid`
 *    (`settings_invalid`). A change that changes nothing is `unchanged`, and
 *    touches no link.
 * 4. The freshness contract is asked, through `checkAll()`, with
 *    `sso.connection.trust`, every operation the change asks and
 *    `sso.link.remove`; `stale` is `freshness_required`.
 * 5. In a savepoint: the change is written and reported (`ConnectionUpdated`),
 *    and what the connection has in flight is voided (`InFlightVoider`); every
 *    link of the connection is deleted and reported removed (`LinkRemoved`, in
 *    id order), and, for each link removed rather than relinked, the identity's
 *    sessions through the connection are revoked
 *    (`RevocationScope::identityInConnection`).
 * 6. Each relinked link's identity is linked to its new subject through
 *    `Links\LinkStore::create()` with the origin `migration`, in the order the
 *    relinks are given (`LinkCreated`). A new subject already linked in the
 *    connection, another relink's included, is `duplicate` at `relinks.<id>`,
 *    and an identity at its link limit `too_many` there: either is `invalid`
 *    and rolls the whole migration back.
 *
 * Its events are dispatched once it commits, in that order
 * (`ConnectionUpdated`, each `LinkRemoved`, each `LinkCreated`), and never when
 * it rolls back (SSO-10.5). The revocation runs inside the transaction, so an
 * adapter that writes through the same Laravel connection commits or rolls back
 * with the migration (decision D5); an exception it throws rolls everything
 * back and propagates. An empty or overlong tenant id is an
 * `InvalidArgumentException`; a database error propagates (SSO-11.4).
 *
 * It holds the lookup, the registry, the management helpers, the link store,
 * the link reporter and the container, none of which keeps anything of one
 * request for the next (SSO-11.2). Resolve it from the container per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SubjectMigration
{
    /** @var string The relinks, as a violation names them. */
    private const string RELINKS = 'relinks';

    /** @var int The most parts a relink gives: the subject, the format and the issuer. */
    private const int MAX_RELINK_PARTS = 3;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $finder
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionService  $connections
     * @param  \SineMacula\Laravel\Sso\Links\LinkStore  $links
     * @param  \SineMacula\Laravel\Sso\Links\LinkEvents  $events
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The tenant-scoped lookup, on the write connection. */
        private ConnectionFinder $finder,

        /** The protocol drivers. */
        private ProtocolManager $protocols,

        /** Validates, asks freshness for, writes and reports the change. */
        private ConnectionService $connections,

        /** Links each relinked identity to its new subject. */
        private LinkStore $links,

        /** Reports each link removed, after commit. */
        private LinkEvents $events,

        /** Resolves the revocation contract at each migration. */
        private Container $container,
    ) {}

    /**
     * Make the change to the tenant's connection, relink each link given to its
     * new subject, and remove each link listed; every link of the connection is
     * one or the other.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  array<string, mixed>  $changes
     * @param  array<array-key, mixed>  $relinks
     * @param  array<array-key, mixed>  $removals
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function migrate(
        string $tenantId,
        string $connectionId,
        #[\SensitiveParameter] array $changes,
        #[\SensitiveParameter] array $relinks,
        array $removals,
        ?ActingIdentity $actor = null,
    ): ConnectionResult {
        return $this->transaction(function () use ($tenantId, $connectionId, $changes, $relinks, $removals, $actor): ConnectionResult {

            $locked = $this->finder->findForUpdate($tenantId, $connectionId);

            if ($locked === null || !$this->protocols->isAvailable($locked->protocol)) {
                return ConnectionResult::refused($locked === null ? FailureReason::CONNECTION_NOT_FOUND : FailureReason::PROTOCOL_UNAVAILABLE);
            }

            $links = self::lockedLinks($locked);

            if (!self::isAccountedFor($links, $relinks, $removals)) {
                return ConnectionResult::refused(FailureReason::LINKS_UNACCOUNTED);
            }

            return $this->migrateLocked($locked, $links, $changes, $relinks, $actor);
        });
    }

    /**
     * Validate the change and the relinks against the locked connection and its
     * locked links; make the change and remove the links in a savepoint; then
     * relink.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, \SineMacula\Laravel\Sso\Models\Link>  $links
     * @param  array<string, mixed>  $changes
     * @param  array<array-key, mixed>  $relinks
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function migrateLocked(
        Connection $locked,
        array $links,
        #[\SensitiveParameter] array $changes,
        #[\SensitiveParameter] array $relinks,
        ?ActingIdentity $actor,
    ): ConnectionResult {
        [$subjects, $violations] = self::relinks($relinks, $links);

        $result = DB::connection(StorageConnection::name())->transaction(
            fn (): ConnectionResult => $this->changed($locked, $changes, $links, $subjects, $violations, $actor),
        );

        $summary = $result->connection;

        if (!$result->isChanged() || $summary === null) {
            return $result;
        }

        return $this->relinkRefusal($locked, $links, $subjects, $actor) ?? ConnectionResult::migrated($summary, $result->changedSettings);
    }

    /**
     * Make the change through the management helpers and, once it is written,
     * delete every link of the connection, report each removed and revoke the
     * sessions of each identity that is not relinked.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, mixed>  $changes
     * @param  array<string, \SineMacula\Laravel\Sso\Models\Link>  $links
     * @param  array<array-key, \SineMacula\Laravel\Sso\Links\LinkSubject>  $subjects
     * @param  list<\SineMacula\Laravel\Sso\Connections\SettingViolation>  $violations
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \RuntimeException
     * @throws \JsonException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function changed(Connection $locked, #[\SensitiveParameter] array $changes, array $links, array $subjects, array $violations, ?ActingIdentity $actor): ConnectionResult
    {
        $result = $this->connections->changeLocked($locked, $changes, $actor, $violations);

        if (!$result->isChanged()) {
            return $result;
        }

        Link::query()->where('connection_id', $locked->id)->delete();

        foreach ($links as $linkId => $link) {

            $identity = new IdentityReference($link->identity_type, $link->identity_id);

            if (!array_key_exists($linkId, $subjects)) {
                $this->container->make(SessionRevocation::class)->revoke(RevocationScope::identityInConnection($locked->tenant_id, $locked->id, $identity));
            }

            $this->events->removed($locked, $identity, $actor);
        }

        return $result;
    }

    /**
     * Link each relinked link's identity to its new subject, in the order the
     * relinks are given; the refusal of the first that cannot be linked, or
     * `null` when every one is.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, \SineMacula\Laravel\Sso\Models\Link>  $links
     * @param  array<array-key, \SineMacula\Laravel\Sso\Links\LinkSubject>  $subjects
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return ?\SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function relinkRefusal(Connection $locked, array $links, array $subjects, ?ActingIdentity $actor): ?ConnectionResult
    {
        foreach ($subjects as $linkId => $subject) {

            $link     = $links[$linkId];
            $identity = new IdentityReference($link->identity_type, $link->identity_id);
            $creation = $this->links->create($locked, $subject, $identity, LinkOrigin::MIGRATION, $actor);

            if ($creation->isRefused()) {

                $code = $creation->status === LinkCreationStatus::LINK_LIMIT_REACHED ? ViolationCode::TOO_MANY : ViolationCode::DUPLICATE;

                return ConnectionResult::invalid([new SettingViolation(SettingRules::path(self::RELINKS, $linkId), $code)]);
            }
        }

        return null;
    }

    /**
     * Run the migration in one transaction on the storage connection (a
     * savepoint inside the caller's), committed only when it changed the
     * connection and rolled back otherwise, so a relink refused after the
     * change was written leaves nothing of it. An exception rolls it back and
     * propagates.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Connections\ConnectionResult  $migration
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \Throwable
     */
    private function transaction(\Closure $migration): ConnectionResult
    {
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        try {

            $result = $migration();

            if ($result->isChanged()) {

                $database->commit();

                return $result;
            }
        } catch (\Throwable $exception) {

            $database->rollBack();

            throw $exception;
        }

        $database->rollBack();

        return $result;
    }

    /**
     * The links of the locked connection, keyed by id, in id order, read with a
     * locking read on the write connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return array<string, \SineMacula\Laravel\Sso\Models\Link>
     */
    private static function lockedLinks(Connection $locked): array
    {
        $links = [];

        foreach (Link::query()->useWritePdo()->where('connection_id', $locked->id)->orderBy('id')->lockForUpdate()->get()->all() as $link) {
            $links[$link->id] = $link;
        }

        return $links;
    }

    /**
     * Whether the relinks and the removals account for every locked link
     * exactly once: each link id in one of the two and not in both, and no id
     * (nor a removal that is not a string) that is not one of the links.
     * Removals listed twice count once.
     *
     * @param  array<string, \SineMacula\Laravel\Sso\Models\Link>  $links
     * @param  array<array-key, mixed>  $relinks
     * @param  array<array-key, mixed>  $removals
     * @return bool
     */
    private static function isAccountedFor(array $links, #[\SensitiveParameter] array $relinks, array $removals): bool
    {
        if (array_filter($removals, static fn (mixed $id): bool => !is_string($id)) !== []) {
            return false;
        }

        // As many ids given as there are links, and every link among them: each
        // link given exactly once, and nothing else
        $given   = [...array_keys($relinks), ...array_unique($removals)];
        $current = array_keys($links);

        return count($given) === count($current) && array_diff($current, $given) === [];
    }

    /**
     * The new subject of each valid relink, by link id, in the order given, and
     * a violation at `relinks.<id>` for each other.
     *
     * @param  array<array-key, mixed>  $relinks
     * @param  array<string, \SineMacula\Laravel\Sso\Models\Link>  $links
     * @return array{0: array<array-key, \SineMacula\Laravel\Sso\Links\LinkSubject>, 1: list<\SineMacula\Laravel\Sso\Connections\SettingViolation>}
     *
     * @throws \InvalidArgumentException
     */
    private static function relinks(#[\SensitiveParameter] array $relinks, array $links): array
    {
        $subjects   = [];
        $violations = [];

        foreach ($relinks as $linkId => $relink) {

            $subject = self::subject($links[$linkId], $relink);

            if ($subject instanceof LinkSubject) {
                $subjects[$linkId] = $subject;
                continue;
            }

            $violations[] = new SettingViolation(SettingRules::path(self::RELINKS, $linkId), $subject);
        }

        return [$subjects, $violations];
    }

    /**
     * The new subject the relink gives the link, or why it gives none: a link
     * that is not active, or a relink of the wrong shape.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @param  mixed  $relink
     * @return \SineMacula\Laravel\Sso\Connections\Enums\ViolationCode|\SineMacula\Laravel\Sso\Links\LinkSubject
     */
    private static function subject(Link $link, #[\SensitiveParameter] mixed $relink): LinkSubject|ViolationCode
    {
        if ($link->state !== LinkState::ACTIVE) {
            return ViolationCode::NOT_ALLOWED;
        }

        return self::isRelink($relink) ? self::built($relink, $link->issuer) : ViolationCode::INVALID_TYPE;
    }

    /**
     * Whether the relink is a list of one to three parts: the subject, a
     * string; then the NameID format and the issuer, each a string or `null`.
     *
     * @param  mixed  $relink
     * @return bool
     *
     * @phpstan-assert-if-true array{0: string, 1?: ?string, 2?: ?string} $relink
     */
    private static function isRelink(#[\SensitiveParameter] mixed $relink): bool
    {
        if (!is_array($relink) || !array_is_list($relink) || count($relink) > self::MAX_RELINK_PARTS) {
            return false;
        }

        $refused = array_filter($relink, static fn (mixed $part, int $index): bool => !is_string($part) && ($index === 0 || $part !== null), ARRAY_FILTER_USE_BOTH);

        return $relink !== [] && $refused === [];
    }

    /**
     * The subject the well-shaped relink gives, its issuer the one given or
     * else the link's own, or `invalid_format` when a part is empty or too long
     * for a link.
     *
     * @param  array{0: string, 1?: ?string, 2?: ?string}  $relink
     * @param  string  $issuer
     * @return \SineMacula\Laravel\Sso\Connections\Enums\ViolationCode|\SineMacula\Laravel\Sso\Links\LinkSubject
     */
    private static function built(#[\SensitiveParameter] array $relink, string $issuer): LinkSubject|ViolationCode
    {
        try {
            return new LinkSubject($relink[2] ?? $issuer, $relink[0], $relink[1] ?? null);
        } catch (\InvalidArgumentException) {
            return ViolationCode::INVALID_FORMAT;
        }
    }
}
