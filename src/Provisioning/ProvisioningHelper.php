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
 * `Events\ResultUnlinked`; the listener creates the identity.
 *
 * Call inside the listener's transaction on the storage connection, and roll it
 * back on a refusal or the identity is left with no link.
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

        /** Takes the enforcement and connection locks in the package's order. */
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

        /** Resolves the transactions manager the claim is bound through. */
        private Container $container,
    ) {}

    /**
     * Link the grant's exact result to the new identity; the grant is claimed
     * first, so a reentrant call or second listener gets no second use.
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
     * Whether the trust versions match, or the response's receipt permits
     * exactly that transition.
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
     * Bind the claim only while a transaction is open; otherwise the manager's
     * records were left by a failed commit.
     *
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant  $grant
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function bind(ProvisioningGrant $grant): void
    {
        $manager = $this->container->bound('db.transactions') ? $this->container->make('db.transactions') : null;

        if (!$manager instanceof DatabaseTransactionsManager || DB::connection(StorageConnection::name())->transactionLevel() === 0) {
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
     * Whether the connection is usable, unexpired, and still under the locked
     * enforcing tenant.
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
     * Whether any row but an expired reservation holds the subject, read with a
     * lock.
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
