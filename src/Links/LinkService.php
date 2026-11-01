<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * The helper that lists an identity's links and removes one (SSO-8.4, SSO-4.5,
 * SSO-1.5), for the application's account and administration screens; who may
 * call it for which identity is the application's authorisation, never the
 * package's.
 *
 * The identity is a reference, or the string `me` for the caller the
 * application passes; `me` without a caller, or any other string, is an
 * `InvalidArgumentException`.
 *
 * `list()` answers the identity's links in every connection, of every tenant,
 * oldest first (by creation time, then id), read on the write connection
 * (SSO-11.3) and matched to the identity byte for byte; a summary never holds
 * the subject.
 *
 * `remove()` goes in one order, and a refusal deletes, revokes and reports
 * nothing:
 *
 * 1. The link is found by its id and the identity, by a plain read on the write
 *    connection. A link that does not exist and another identity's are both
 *    `link_not_found`, so nothing is revealed of links that are not the
 *    identity's.
 * 2. The freshness contract is asked with `sso.link.remove` and its maximum
 *    age: `stale` is `freshness_required`.
 * 3. In one transaction on the storage connection (a savepoint inside the
 *    caller's): the link's connection is locked, then the link is read again
 *    locked, and is `link_not_found` when it has gone or now names another
 *    identity; it is deleted through the model; `Contracts\SessionRevocation`,
 *    resolved from the container at that moment, is called with the identity's
 *    sessions through the connection (`RevocationScope::identityInConnection`);
 *    and `LinkRemoved` is reported after commit.
 *
 * The revocation runs inside the transaction, so an adapter that writes through
 * the same Laravel connection commits or rolls back with the removal (decision
 * D5); an exception it throws rolls the removal back, with nothing reported,
 * and propagates. Removing an identity's last link is allowed: the application
 * decides whether the identity can still sign in.
 *
 * A database error propagates (SSO-11.4). It holds the freshness gate, the
 * reporter and the container, none of which keeps anything of one request for
 * the next (SSO-11.2). Resolve it from the container per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkService
{
    /** @var string The identity that names the caller. */
    public const string ME = 'me';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Links\LinkEvents  $events
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Asks the freshness contract before a link is removed. */
        private FreshnessGate $freshness,

        /** Reports each link removed, after commit. */
        private LinkEvents $events,

        /** Resolves the revocation contract at each removal. */
        private Container $container,
    ) {}

    /**
     * The identity's links, oldest first.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference|string  $identity
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return list<\SineMacula\Laravel\Sso\Links\LinkSummary>
     *
     * @throws \InvalidArgumentException
     */
    public function list(IdentityReference|string $identity, ?IdentityReference $caller = null): array
    {
        $reference = self::identity($identity, $caller);

        $links = Link::query()
            ->useWritePdo()
            ->where('identity_type', $reference->type)
            ->where('identity_id', $reference->id)
            ->orderBy('created_at')
            ->orderBy('id')
            ->get()
            ->all();

        return self::summaries(array_filter($links, static fn (Link $link): bool => self::isOwnedBy($link, $reference)));
    }

    /**
     * Remove the identity's link with the id, and revoke the identity's
     * sessions established through its connection.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference|string  $identity
     * @param  string  $linkId
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Links\LinkResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function remove(IdentityReference|string $identity, string $linkId, ?IdentityReference $caller = null, ?ActingIdentity $actor = null): LinkResult
    {
        $reference = self::identity($identity, $caller);
        $link      = self::owned($linkId, $reference, false);

        if ($link === null) {
            return LinkResult::refused(FailureReason::LINK_NOT_FOUND);
        }

        if (!$this->freshness->check(FreshnessOperation::LINK_REMOVE)->isFresh()) {
            return LinkResult::refused(FailureReason::FRESHNESS_REQUIRED);
        }

        return DB::connection(StorageConnection::name())->transaction(fn (): LinkResult => $this->delete($link, $reference, $actor));
    }

    /**
     * Delete the link under its connection's lock, once read again locked and
     * still the identity's; revoke the identity's sessions through the
     * connection; and report the removal.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $found
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Links\LinkResult
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function delete(Link $found, IdentityReference $identity, ?ActingIdentity $actor): LinkResult
    {
        $connection = Connection::query()->useWritePdo()->whereKey($found->connection_id)->lockForUpdate()->first();

        if ($connection === null) {
            return LinkResult::refused(FailureReason::LINK_NOT_FOUND);
        }

        $locked = self::owned($found->id, $identity, true);

        if ($locked === null) {
            return LinkResult::refused(FailureReason::LINK_NOT_FOUND);
        }

        $locked->delete();

        $this->container->make(SessionRevocation::class)->revoke(RevocationScope::identityInConnection($connection->tenant_id, $connection->id, $identity));

        $this->events->removed($connection, $identity, $actor);

        return LinkResult::removed(LinkSummary::of($locked, $connection));
    }

    /**
     * The identity's link with the id, read on the write connection, locked for
     * update when asked, or `null` when there is none or it is another
     * identity's.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  bool  $lock
     * @return ?\SineMacula\Laravel\Sso\Models\Link
     */
    private static function owned(string $linkId, IdentityReference $identity, bool $lock): ?Link
    {
        $query = Link::query()
            ->useWritePdo()
            ->whereKey($linkId)
            ->where('identity_type', $identity->type)
            ->where('identity_id', $identity->id);

        $link = ($lock ? $query->lockForUpdate() : $query)->first();

        return $link !== null && self::isOwnedBy($link, $identity) ? $link : null;
    }

    /**
     * The summary of each link, with its connection's tenant and protocol, in
     * the order given; a link whose connection no longer exists is left out.
     *
     * @param  array<int, \SineMacula\Laravel\Sso\Models\Link>  $links
     * @return list<\SineMacula\Laravel\Sso\Links\LinkSummary>
     */
    private static function summaries(array $links): array
    {
        if ($links === []) {
            return [];
        }

        $ids         = array_map(static fn (Link $link): string => $link->connection_id, $links);
        $connections = Connection::query()->useWritePdo()->whereKey($ids)->get()->keyBy('id')->all();
        $summaries   = [];

        foreach ($links as $link) {

            $connection = $connections[$link->connection_id] ?? null;

            if (!$connection instanceof Connection) {
                continue;
            }

            $summaries[] = LinkSummary::of($link, $connection);
        }

        return $summaries;
    }

    /**
     * Whether the link is the identity's, byte for byte, whatever the
     * collation.
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
     * The identity named: the reference given, or the caller for `me`.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference|string  $identity
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     *
     * @throws \InvalidArgumentException
     */
    private static function identity(IdentityReference|string $identity, ?IdentityReference $caller): IdentityReference
    {
        return match (true) {
            $identity instanceof IdentityReference => $identity,
            $identity !== self::ME                 => throw new \InvalidArgumentException(sprintf('An identity is a reference, or [%s] for the caller.', self::ME)),
            $caller === null                       => throw new \InvalidArgumentException(sprintf('The identity [%s] names the caller, and no caller was given.', self::ME)),
            default                                => $caller,
        };
    }
}
