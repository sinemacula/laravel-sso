<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * Lists an identity's links and removes one; who may call it for whom is the
 * application's authorisation.
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
     * The identity's links in every connection, oldest first; `me` names the
     * caller.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference|string  $identity
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return list<\SineMacula\Laravel\Sso\Links\LinkSummary>
     *
     * @throws \InvalidArgumentException
     */
    public function list(IdentityReference|string $identity, ?Caller $caller = null): array
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
     * Remove the identity's link and revoke its sessions through the
     * connection, in one transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference|string  $identity
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Links\LinkResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function remove(IdentityReference|string $identity, string $linkId, ClientContext $client, ?Caller $caller = null): LinkResult
    {
        $reference = self::identity($identity, $caller);
        $link      = self::owned($linkId, $reference, false);

        if ($link === null) {
            return LinkResult::refused(FailureReason::LINK_NOT_FOUND);
        }

        return DB::connection(StorageConnection::name())->transaction(fn (): LinkResult => $this->delete($link, $reference, $caller, $client));
    }

    /**
     * Under the connection's lock, ask freshness, then delete the link if still
     * the identity's, revoke the sessions, and report it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $found
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Links\LinkResult
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function delete(Link $found, IdentityReference $identity, ?Caller $caller, ClientContext $client): LinkResult
    {
        $connection = Connection::query()->useWritePdo()->whereKey($found->connection_id)->lockForUpdate()->first();

        $locked = $connection === null ? null : self::owned($found->id, $identity, true);

        if ($connection === null || $locked === null) {
            return LinkResult::refused(FailureReason::LINK_NOT_FOUND);
        }

        if (!$this->freshness->check(FreshnessOperation::LINK_REMOVE, $caller)->isFresh()) {
            return LinkResult::refused(FailureReason::FRESHNESS_REQUIRED);
        }

        $locked->delete();

        $connection->increment('links_version');

        $this->container->make(SessionRevocation::class)->revoke(RevocationScope::identityInConnection($connection->tenant_id, $connection->id, $identity, $locked->id));

        $this->events->removed($connection, $identity, $client, $caller);

        return LinkResult::removed(LinkSummary::of($locked, $connection));
    }

    /**
     * The identity's link with the id, locked when asked, or `null`.
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
     * Each link's summary in order, leaving out links whose connection is gone.
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
     * The identity named: the reference given, or the caller's for `me`.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference|string  $identity
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     *
     * @throws \InvalidArgumentException
     */
    private static function identity(IdentityReference|string $identity, ?Caller $caller): IdentityReference
    {
        return match (true) {
            $identity instanceof IdentityReference => $identity,
            $identity !== self::ME                 => throw new \InvalidArgumentException(sprintf('An identity is a reference, or [%s] for the caller.', self::ME)),
            $caller === null                       => throw new \InvalidArgumentException(sprintf('The identity [%s] names the caller, and no caller was given.', self::ME)),
            default                                => $caller->identity,
        };
    }
}
