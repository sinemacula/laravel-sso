<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
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
 * Changes a subject-defining setting on a connection with links, relinking or
 * removing every link in the same transaction.
 *
 * Every link must be either relinked or removed, so one created after the call
 * was prepared is never dropped by accident.
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

    /** @var int The most parts a relink gives: subject, format and issuer. */
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
     * Each relink maps a link id to `[subject, ?format, ?issuer]`; the issuer
     * defaults to the link's own.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  array<string, mixed>  $changes
     * @param  array<array-key, mixed>  $relinks
     * @param  array<array-key, mixed>  $removals
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
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
        ClientContext $client,
        ?Caller $caller = null,
    ): ConnectionResult {
        return $this->transaction(function () use ($tenantId, $connectionId, $changes, $relinks, $removals, $client, $caller): ConnectionResult {

            $locked = $this->finder->findForUpdate($tenantId, $connectionId);

            if ($locked === null || !$this->protocols->isAvailable($locked->protocol)) {
                return ConnectionResult::refused($locked === null ? FailureReason::CONNECTION_NOT_FOUND : FailureReason::PROTOCOL_UNAVAILABLE);
            }

            $links = self::lockedLinks($locked);

            if (!self::isAccountedFor($links, $relinks, $removals)) {
                return ConnectionResult::refused(FailureReason::LINKS_UNACCOUNTED);
            }

            return $this->migrateLocked($locked, $links, $changes, $relinks, $caller, $client);
        });
    }

    /**
     * Make the change and remove the links in a savepoint, then relink.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, \SineMacula\Laravel\Sso\Models\Link>  $links
     * @param  array<string, mixed>  $changes
     * @param  array<array-key, mixed>  $relinks
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
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
        ?Caller $caller,
        ClientContext $client,
    ): ConnectionResult {
        [$subjects, $violations] = self::relinks($relinks, $links);

        $result = DB::connection(StorageConnection::name())->transaction(
            fn (): ConnectionResult => $this->changed($locked, $changes, $links, $subjects, $violations, $caller, $client),
        );

        $summary = $result->connection;

        if (!$result->isChanged() || $summary === null) {
            return $result;
        }

        return $this->relinkRefusal($locked, $links, $subjects, $caller, $client) ?? ConnectionResult::migrated($summary, $result->changedSettings);
    }

    /**
     * Make the change, then delete every link, revoking sessions of removed and
     * domain-provenance links, which the new row could not reach.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, mixed>  $changes
     * @param  array<string, \SineMacula\Laravel\Sso\Models\Link>  $links
     * @param  array<array-key, \SineMacula\Laravel\Sso\Links\LinkSubject>  $subjects
     * @param  list<\SineMacula\Laravel\Sso\Connections\SettingViolation>  $violations
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \RuntimeException
     * @throws \JsonException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function changed(
        Connection $locked,
        #[\SensitiveParameter] array $changes,
        array $links,
        array $subjects,
        array $violations,
        ?Caller $caller,
        ClientContext $client,
    ): ConnectionResult {
        $result = $this->connections->changeLocked($locked, $changes, $client, $caller, $violations);

        if (!$result->isChanged()) {
            return $result;
        }

        Link::query()->where('connection_id', $locked->id)->delete();

        foreach ($links as $linkId => $link) {

            $identity = new IdentityReference($link->identity_type, $link->identity_id);

            if (!array_key_exists($linkId, $subjects) || $link->domain_provenance) {
                $this->container->make(SessionRevocation::class)->revoke(RevocationScope::identityInConnection($locked->tenant_id, $locked->id, $identity, $link->id));
            }

            $this->events->removed($locked, $identity, $client, $caller);
        }

        return $result;
    }

    /**
     * Link each identity to its new subject in the order given; the first
     * refusal, or `null`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, \SineMacula\Laravel\Sso\Models\Link>  $links
     * @param  array<array-key, \SineMacula\Laravel\Sso\Links\LinkSubject>  $subjects
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return ?\SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function relinkRefusal(Connection $locked, array $links, array $subjects, ?Caller $caller, ClientContext $client): ?ConnectionResult
    {
        foreach ($subjects as $linkId => $subject) {

            $link     = $links[$linkId];
            $identity = new IdentityReference($link->identity_type, $link->identity_id);
            $creation = $this->links->create($locked, $subject, $identity, LinkOrigin::MIGRATION, $client, $caller);

            if ($creation->isRefused()) {

                $code = $creation->status === LinkCreationStatus::LINK_LIMIT_REACHED ? ViolationCode::TOO_MANY : ViolationCode::DUPLICATE;

                return ConnectionResult::invalid([new SettingViolation(SettingRules::path(self::RELINKS, $linkId), $code)]);
            }

            if (!$link->domain_provenance) {
                continue;
            }

            self::keepDomainProvenance((string) $creation->linkId());
        }

        return null;
    }

    /**
     * Keep verified domain provenance on the new row, since only a confirming
     * `link` clears it.
     *
     * @param  string  $linkId
     * @return void
     */
    private static function keepDomainProvenance(string $linkId): void
    {
        Link::query()->useWritePdo()->whereKey($linkId)->update(['provenance' => LinkOrigin::VERIFIED_DOMAIN->value]);
    }

    /**
     * Commit only when the connection changed, so a relink refused after the
     * change was written leaves nothing of it.
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
     * The connection's links keyed by id, by a locking read in id order.
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
     * Whether the relinks and removals name every locked link exactly once and
     * nothing else; a removal listed twice counts once.
     *
     * @param  array<string, \SineMacula\Laravel\Sso\Models\Link>  $links
     * @param  array<array-key, mixed>  $relinks
     * @param  array<array-key, mixed>  $removals
     * @return bool
     */
    private static function isAccountedFor(array $links, #[\SensitiveParameter] array $relinks, array $removals): bool
    {
        $removed = array_filter($removals, is_string(...));

        if (count($removed) !== count($removals)) {
            return false;
        }

        $given   = [...array_keys($relinks), ...array_unique($removed)];
        $current = array_keys($links);

        return count($given) === count($current) && array_diff($current, $given) === [];
    }

    /**
     * The new subject of each valid relink, and a violation for each other.
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
     * The new subject, or why none: only an active link can be relinked.
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
     * Whether the relink is a list of a subject string, then an optional
     * nullable format and issuer.
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
     * The subject the relink gives, or `invalid_format` for a part of the wrong
     * length.
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
