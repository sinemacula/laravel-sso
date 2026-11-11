<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Provisioning;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Completion\ProvisioningOffer;
use SineMacula\Laravel\Sso\Completion\VerifiedDeadlines;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\RecheckLock;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Metadata\TransitionReceipts;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Links a new identity to an unlinked `sign_in` result, once, for a listener of
 * `Events\ResultUnlinked` (SSO-8.6, `docs/design/linking.md`). The package
 * creates no identity, principal or membership: the listener does, and that the
 * identity is new is the adapter's obligation, since the package holds only an
 * opaque reference. Resolving an existing identity from an email or any mapped
 * attribute is forbidden: attaching to one goes through the `link` purpose or a
 * verified domain.
 *
 * `link()` goes in a fixed order:
 *
 * 1. The bound `Contracts\Linker` not backed by `Contracts\LinkStorage` is a
 *    `LogicException`, with nothing written and the grant unspent: a link made
 *    here would be one the resolver ignores.
 * 2. The grant is claimed, before anything else, so a reentrant call or a
 *    second listener gets no second use, and bound to the listener's outermost
 *    transaction on the storage connection, or to the helper's own once it
 *    begins: only that transaction's rollback lets the grant be claimed again,
 *    so a listener may retry its whole transaction. A grant given another
 *    result object than it is bound to (identical fields are not enough) is
 *    `grant_wrong_result`: that is a listener's bug, and recovery is a new
 *    flow. A grant that is used, closed or was not issued for a running
 *    dispatch is `grant_invalid`. Every refusal spends the grant for good, so a
 *    refused attempt can never be repeated for another identity.
 * 3. One transaction on the storage connection (a savepoint inside the
 *    listener's) takes the frozen lock order, each by a locking read on the
 *    write connection: the enforcing tenant's rule and connections
 *    (`Handoffs\HandoffRecheck::lock()`, with the feature on under the default
 *    contract), or the connection alone; the request, by the id claimed; then
 *    the links.
 * 4. Under those locks, `request_unavailable`: the connection gone or no longer
 *    usable, what was fetched for it expired, the enforcing tenant moved, or
 *    the request not consumed, finished, voided, or of another trust version
 *    than the connection's, unless the response's own receipt permits exactly
 *    that transition. Then `expired`: the verified response's deadline has
 *    passed (`Completion\VerifiedDeadlines`). Then `subject_already_linked`: a
 *    row of any state holds the subject, an expired reservation apart, which is
 *    logically absent.
 * 5. `Contracts\LinkStorage::create()` inserts the active link with
 *    `provisioning` as its origin, under the identity's limit
 *    (`link_limit_reached`) and the unique index, raises the connection's links
 *    version and reports `LinkCreated`, which waits for the listener's outer
 *    commit and never comes on its rollback.
 *
 * A refusal is a value, never thrown, and writes nothing. A listener wraps the
 * identity, its membership and this call in one transaction on the storage
 * connection and must roll it back on a refusal, or it leaves an identity with
 * no link; its writes through another connection are not atomic with the link.
 * A link committed here can survive a later completion failure, which is the
 * accepted consequence of provisioning outside the package's locks.
 *
 * Resolve it from the container per dispatch. It holds the locks, the drivers'
 * registry, the metadata expiry, the deadlines, the storage binding, the clock,
 * the offer and the container the transactions manager is resolved from on each
 * call, none of which keeps anything of one completion for the next (SSO-11.2).
 * A database error and a contract's exception propagate (SSO-11.4); on
 * PostgreSQL under `REPEATABLE READ`, a transaction whose snapshot predates a
 * change it waited on fails to serialise instead of refusing, and on InnoDB
 * under `REPEATABLE READ` two first sign-ins can deadlock on gap locks: both
 * are worth a retry of the listener's whole transaction.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProvisioningHelper
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffRecheck  $locks
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataExpiry  $metadata
     * @param  \SineMacula\Laravel\Sso\Completion\VerifiedDeadlines  $deadlines
     * @param  \SineMacula\Laravel\Sso\Links\LinkStorageBinding  $storage
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Completion\ProvisioningOffer  $offer
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Takes the guard and the connection, in the package's lock order. */
        private HandoffRecheck $locks,

        /** Whether the connection is still usable under its lock. */
        private ProtocolManager $protocols,

        /** Whether what was fetched for the locked connection has expired. */
        private MetadataExpiry $metadata,

        /** Whether the verified response's deadline has passed. */
        private VerifiedDeadlines $deadlines,

        /** Creates the link. */
        private LinkStorageBinding $storage,

        /** The clock a held reservation is judged against. */
        private Clock $clock,

        /** Whether a dispatch issued the grant. */
        private ProvisioningOffer $offer,

        /** Resolves the transactions manager the grant's claim is bound through. */
        private Container $container,
    ) {}

    /**
     * Link the exact result the grant is bound to, to the new identity, for the
     * client, whose IP address and user agent `LinkCreated` carries.
     *
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant  $grant
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Provisioning\ProvisioningResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function link(ProvisioningGrant $grant, #[\SensitiveParameter] VerifiedResult $result, IdentityReference $identity, ClientContext $client): ProvisioningResult
    {
        $this->storage->require('The provisioning helper');

        $mismatched = $grant->isUsable() && !$grant->isBoundTo($result);
        $requestId  = $grant->claim($result);

        if ($requestId === null || !$this->offer->isRegistered($grant)) {
            return $mismatched ? ProvisioningResult::grantWrongResult() : ProvisioningResult::grantInvalid();
        }

        $this->bind($grant);

        return DB::connection(StorageConnection::name())->transaction(function () use ($grant, $requestId, $result, $identity, $client): ProvisioningResult {

            $this->bind($grant);

            $answer = $this->underLocks($grant, $requestId, $result, $identity, $client);

            if ($answer->isRefused()) {
                $grant->refuse();
            }

            return $answer;
        });
    }

    /**
     * Whether the request is consumed, not finished and not voided.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return bool
     */
    private static function isUnfinished(AuthorizationRequest $request): bool
    {
        return $request->consumed_at !== null && $request->completed_at === null && $request->voided_at === null;
    }

    /**
     * Whether the request is of the connection's trust version, or the
     * response's own receipt permits exactly the transition between them.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant  $grant
     * @return bool
     */
    private static function isOfCurrentTrust(AuthorizationRequest $request, Connection $connection, ProvisioningGrant $grant): bool
    {
        return $request->trust_version === $connection->trust_version
            || TransitionReceipts::permits($grant->transitionReceipt(), $connection, $request);
    }

    /**
     * Bind the grant's claim to the outermost transaction open on the storage
     * connection, when a transactions manager is bound.
     *
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant  $grant
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function bind(ProvisioningGrant $grant): void
    {
        $manager = $this->container->bound('db.transactions') ? $this->container->make('db.transactions') : null;

        if (!$manager instanceof DatabaseTransactionsManager) {
            return;
        }

        $grant->bind($manager, StorageConnection::resolvedName());
    }

    /**
     * Take the locks in order, and make the link if everything still stands.
     *
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant  $grant
     * @param  string  $requestId
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Provisioning\ProvisioningResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function underLocks(
        ProvisioningGrant $grant,
        string $requestId,
        #[\SensitiveParameter] VerifiedResult $result,
        IdentityReference $identity,
        ClientContext $client,
    ): ProvisioningResult {
        $lock       = $this->locks->lock($result->tenantId, $result->connectionId, $result->application);
        $connection = $lock->connection;
        $request    = AuthorizationRequest::query()->useWritePdo()->lockForUpdate()->whereKey($requestId)->first();

        if ($connection === null || $request === null || !$this->stands($lock, $connection, $request, $grant)) {
            return ProvisioningResult::requestUnavailable();
        }

        if ($this->deadlines->hasPassed($grant->verifiedUntil())) {
            return ProvisioningResult::expired();
        }

        return $this->linked($connection, $result, $identity, $client);
    }

    /**
     * Whether the connection and the request still stand under the locks.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant  $grant
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function stands(RecheckLock $lock, Connection $connection, AuthorizationRequest $request, ProvisioningGrant $grant): bool
    {
        return $this->isConnectionUsable($lock, $connection)
            && self::isUnfinished($request)
            && self::isOfCurrentTrust($request, $connection, $grant);
    }

    /**
     * Whether the connection is usable, what was fetched for it has not
     * expired, and the rule locked is still the enforcing tenant's.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isConnectionUsable(RecheckLock $lock, Connection $connection): bool
    {
        return $this->protocols->isUsable($connection)
            && !$this->metadata->isExpired($connection)
            && ($lock->enforcement?->isCurrent() ?? true);
    }

    /**
     * Make the link, unless the subject is held.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Provisioning\ProvisioningResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function linked(Connection $connection, #[\SensitiveParameter] VerifiedResult $result, IdentityReference $identity, ClientContext $client): ProvisioningResult
    {
        $subject = LinkSubject::of($result);

        if ($this->isHeld($connection, $subject)) {
            return ProvisioningResult::subjectAlreadyLinked();
        }

        return ProvisioningResult::fromCreation($this->storage->require('The provisioning helper')->create(
            $connection,
            $subject,
            $identity,
            LinkOrigin::PROVISIONING,
            $client,
            application: $result->application,
            purpose: $result->purpose,
            reference: $result->requestReference,
        ));
    }

    /**
     * Whether a row holds the subject in the connection, by a locking read: any
     * row but an expired reservation, which is logically absent and which the
     * store replaces.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @return bool
     */
    private function isHeld(Connection $connection, LinkSubject $subject): bool
    {
        $row = Link::query()->useWritePdo()->where('connection_id', $connection->id)->where('subject_key', $subject->key())->lockForUpdate()->first();

        return $row !== null && !$this->isExpiredReservation($row);
    }

    /**
     * Whether the row is a reservation whose expiry is not after now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $row
     * @return bool
     */
    private function isExpiredReservation(Link $row): bool
    {
        return $row->state === LinkState::RESERVED && !($row->reservation_expires_at?->isAfter($this->clock->now()) ?? false);
    }
}
