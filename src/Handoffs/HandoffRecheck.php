<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\PurposeBranch;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Admission;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Judgement;
use SineMacula\Laravel\Sso\Handoffs\Redemption\LinkBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\ReauthenticationBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext;
use SineMacula\Laravel\Sso\Handoffs\Redemption\SignInBranch;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\IdentityLock;
use SineMacula\Laravel\Sso\Linking\LinkConfirmationGate;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Rechecks a redemption under its locks and makes the purpose's writes.
 *
 * Each call runs inside the redeemer's storage transaction; lock() comes first.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class HandoffRecheck
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $connections
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Contracts\Enforcement  $enforcement
     * @param  \SineMacula\Laravel\Sso\Links\LinkStorageBinding  $storage
     * @param  \SineMacula\Laravel\Sso\Linking\IdentityLock  $identities
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Locks the connection, of the tenant, when no enforcement is locked. */
        private ConnectionFinder $connections,

        /** Whether the connection is still usable. */
        private ProtocolManager $protocols,

        /** Locks, or answers, the enforcement of the connection's tenant. */
        private Enforcement $enforcement,

        /** Removes the reservation of a code refused after it was consumed. */
        private LinkStorageBinding $storage,

        /** Locks the identity of a reservation or of a `link`. */
        private IdentityLock $identities,

        /** Resolves the branch of the result's purpose. */
        private Container $container,
    ) {}

    /**
     * Take the locks a redemption holds before it locks its code.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $application
     * @param  ?string  $reservationId
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $confirming
     * @return \SineMacula\Laravel\Sso\Handoffs\RecheckLock
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function lock(string $tenantId, string $connectionId, string $application, ?string $reservationId = null, ?IdentityReference $confirming = null): RecheckLock
    {
        self::assertInTransaction();

        $reservation = self::reservationOf($connectionId, $reservationId);
        $guarded     = $confirming ?? IdentityReference::fromColumns($reservation?->identity_type, $reservation?->identity_id);

        if ($guarded !== null) {
            $this->identities->acquire($guarded);
        }

        $held        = $confirming !== null && IdentityLock::hasHeldDomainLink($confirming);
        $ids         = array_values(array_unique([$connectionId, ...($confirming === null ? [] : LinkConfirmationGate::connectionsHolding($confirming))]));
        $enforcement = $this->enforcement instanceof DatabaseEnforcement ? $this->enforcement->lock($tenantId, $application, $ids) : null;
        $locked      = $enforcement === null ? $this->lockedConnections($tenantId, $connectionId, $ids) : $enforcement->connections;
        $connection  = self::connectionOf($locked, $tenantId, $connectionId);
        $domain      = $connection === null ? null : self::lockedDomain($reservation);

        $lockedIds = array_map(static fn (Connection $row): string => $row->id, $locked);

        return RecheckLock::held($tenantId, $connectionId, $application, $connection, $enforcement, $domain, $guarded, $lockedIds, $held);
    }

    /**
     * Check the connection, enforcement and purpose rules again under the lock.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $binding
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function recheck(VerifiedResult $result, HandoffBinding $binding, RecheckLock $lock, ClientContext $client, ?Caller $caller = null): RecheckOutcome
    {
        return $this->judged($result, $binding, $lock, $client, $caller)->outcome;
    }

    /**
     * Recheck, and make the purpose's writes when it passes.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $binding
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Admission
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function admit(VerifiedResult $result, HandoffBinding $binding, RecheckLock $lock, ClientContext $client, ?Caller $caller = null): Admission
    {
        $judgement = $this->judged($result, $binding, $lock, $client, $caller);

        if ($judgement->outcome !== RecheckOutcome::PASSED || $lock->connection === null) {
            return Admission::refused($judgement->outcome);
        }

        $context = new RedemptionContext($result, $binding, $lock, $lock->connection, $client, $caller, $judgement->linkProvenance);

        return $this->branch($result)->admit($context)->under($judgement->enforcementVersion);
    }

    /**
     * Remove the reservation of a code refused after it was consumed.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $binding
     * @param  string  $connectionId
     * @return void
     *
     * @throws \LogicException
     */
    public function discardReservation(HandoffBinding $binding, string $connectionId): void
    {
        self::assertInTransaction();

        if ($binding->reservationId === null) {
            return;
        }

        $this->storage->require('Discarding a reservation')->reservations()->deleteRefused($connectionId, $binding->reservationId, $binding->handoffReference);
    }

    /**
     * Record on the locked connection that a `sign_in` through it was redeemed.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @return void
     *
     * @throws \LogicException
     */
    public function acknowledgeSignIn(VerifiedResult $result, RecheckLock $lock): void
    {
        if ($result->purpose !== Purpose::SIGN_IN) {
            self::outOfTurn(sprintf('Only a [sign_in] result completes a sign-in, not a [%s] one.', $result->purpose->value));
        }

        self::assertHeldFor($lock, $result);

        $connection = $lock->connection ?? self::outOfTurn('The connection a sign-in is acknowledged through is gone: recheck the handoff first.');

        if ($connection->has_completed_sign_in) {
            return;
        }

        $connection->forceFill(['has_completed_sign_in' => true])->save();
    }

    /**
     * Judge the redemption under the lock.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $binding
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Judgement
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function judged(VerifiedResult $result, HandoffBinding $binding, RecheckLock $lock, ClientContext $client, ?Caller $caller): Judgement
    {
        self::assertHeldFor($lock, $result);

        $connection = $lock->connection;
        $policy     = self::isIssuedUnder($binding, $connection) ? $this->usablePolicy($lock) : null;

        if ($connection === null || $policy === null) {
            return Judgement::of(RecheckOutcome::CONNECTION_UNAVAILABLE);
        }

        if (!$policy->isSatisfiedBy($connection->id)) {
            return Judgement::of(RecheckOutcome::ENFORCEMENT_UNSATISFIED);
        }

        return $this->branch($result)->judge(new RedemptionContext($result, $binding, $lock, $connection, $client, $caller))->under($policy->version);
    }

    /**
     * Whether the binding names the locked connection's trust version.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $binding
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    private static function isIssuedUnder(HandoffBinding $binding, ?Connection $connection): bool
    {
        return $connection !== null && $binding->trustVersion !== null && $binding->trustVersion === $connection->trust_version;
    }

    /**
     * The policy to judge by, or `null` when the connection is unavailable.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @return ?\SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     *
     * @throws \InvalidArgumentException
     */
    private function usablePolicy(RecheckLock $lock): ?EnforcementPolicy
    {
        $connection = $lock->connection;

        return $connection !== null && $this->protocols->isUsable($connection) ? $this->policy($lock) : null;
    }

    /**
     * The locked policy, or the bound contract's when none was locked; `null`
     * when the enforcing tenant moved.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @return ?\SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     *
     * @throws \InvalidArgumentException
     */
    private function policy(RecheckLock $lock): ?EnforcementPolicy
    {
        $locked = $lock->enforcement;

        if ($locked === null) {
            return $this->enforcement->policy($lock->tenantId, $lock->application);
        }

        return $locked->isCurrent() ? $locked->policy() : null;
    }

    /**
     * Refuse a call outside a transaction or under another result's lock.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertHeldFor(RecheckLock $lock, VerifiedResult $result): void
    {
        self::assertInTransaction();

        if ($lock->isFor($result)) {
            return;
        }

        self::outOfTurn('A handoff is rechecked under the lock taken for its result\'s tenant, connection and application.');
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
        if (DB::connection(StorageConnection::name())->transactionLevel() > 0) {
            return;
        }

        self::outOfTurn('A handoff is rechecked inside the redeemer\'s transaction on the package\'s storage connection (decision D5).');
    }

    /**
     * Refuse a call made out of turn.
     *
     * @param  string  $message
     * @return never
     *
     * @throws \LogicException
     */
    private static function outOfTurn(string $message): never
    {
        throw new \LogicException($message);
    }

    /**
     * Find the reservation by a plain read; it is locked only after the code,
     * and the branch confirms it under the lock.
     *
     * @param  string  $connectionId
     * @param  ?string  $reservationId
     * @return ?\SineMacula\Laravel\Sso\Models\Link
     */
    private static function reservationOf(string $connectionId, ?string $reservationId): ?Link
    {
        if ($reservationId === null) {
            return null;
        }

        return Link::query()->useWritePdo()->where('reservation_id', $reservationId)->where('connection_id', $connectionId)->first();
    }

    /**
     * Lock the reservation's domain claim.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Link  $reservation
     * @return ?\SineMacula\Laravel\Sso\Models\Domain
     */
    private static function lockedDomain(?Link $reservation): ?Domain
    {
        $domainId = $reservation?->reservation_domain_id;

        return $domainId === null ? null : Domain::query()->useWritePdo()->lockForUpdate()->whereKey($domainId)->first();
    }

    /**
     * The locked connection with the id, of exactly the tenant, or `null`.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $locked
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     */
    private static function connectionOf(array $locked, string $tenantId, string $connectionId): ?Connection
    {
        foreach ($locked as $connection) {

            if ($connection->id === $connectionId && $connection->tenant_id === $tenantId) {
                return $connection;
            }
        }

        return null;
    }

    /**
     * Lock the connections in id order when enforcement locked none.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  list<string>  $ids
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     *
     * @throws \InvalidArgumentException
     */
    private function lockedConnections(string $tenantId, string $connectionId, array $ids): array
    {
        if (count($ids) > 1) {
            sort($ids, SORT_STRING);

            return array_values(Connection::query()->useWritePdo()->whereIn('id', $ids)->orderBy('id')->lockForUpdate()->get()->all());
        }

        $connection = $this->connections->findForUpdate($tenantId, $connectionId);

        return $connection === null ? [] : [$connection];
    }

    /**
     * The branch of the result's purpose.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Sso\Contracts\PurposeBranch
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function branch(VerifiedResult $result): PurposeBranch
    {
        return match ($result->purpose) {
            Purpose::SIGN_IN        => $this->container->make(SignInBranch::class),
            Purpose::LINK           => $this->container->make(LinkBranch::class),
            Purpose::REAUTHENTICATE => $this->container->make(ReauthenticationBranch::class),
        };
    }
}
