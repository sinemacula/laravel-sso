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
use SineMacula\Laravel\Sso\Handoffs\Redemption\LinkBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\ReauthenticationBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext;
use SineMacula\Laravel\Sso\Handoffs\Redemption\SignInBranch;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The checks every redemption of a handoff code makes again (SSO-4.6, SSO-8.5,
 * SSO-8.8, SSO-9.9), the purpose's writes, and the acknowledgement of a
 * completed sign-in (SSO-4.3): the package's own redemption asks them, and so
 * does an adapter that redeems its own codes (under `laravel-iam`,
 * `laravel-authentication`'s handoff codes, AUTH-3.10), with the verified
 * result its code carries and a `Handoffs\HandoffBinding` of what that code was
 * bound to.
 *
 * Each runs only inside a transaction the redeemer has open on the package's
 * storage connection, the one that consumes its code, so the locks, the checks,
 * the consumption, the activation, the acknowledgement and the session the
 * redeemer writes commit or roll back together; called with no transaction open
 * there, each throws a `LogicException` (decision D5). A redeemer writing
 * through another connection is not atomic with them.
 *
 * `lock()` comes first, before the redeemer locks its own code, so every
 * redemption takes the package's lock order (`flows.md`): the tenant's
 * enforcement row, then connection rows in id order, then, for a code bound to
 * a reservation, its domain claim (found by a plain read of the reservation,
 * which `recheck()` confirms under the lock), then the code. Under the
 * package's default `Contracts\Enforcement` (`DatabaseEnforcement`) with the
 * `enforcement` feature on, it asks the bound
 * `Contracts\EnforcementInheritance` for the enforcing tenant, locks that
 * tenant's row (inserted unconfigured when it has none,
 * `Enforcement\EnforcementLock`), and then, in one locking statement in id
 * order, the result's connection and the connections the rule names. Otherwise
 * (the feature off, or another contract bound) it locks the connection alone,
 * and asks nothing. A rule change waits for the redeemer's transaction, and its
 * revocation then sees the session the redeemer wrote; a redeemer that waited
 * on a change sees the rule as changed. On PostgreSQL under `REPEATABLE READ`,
 * a redeemer that waited may instead fail to serialise: the error propagates,
 * and the redeemer retries its whole transaction, never a part of it.
 *
 * `recheck()` takes that lock, for the result's tenant, connection and
 * application (another is a `LogicException`), and answers, in this order, the
 * first that refuses:
 *
 * 1. `connection_unavailable`: the result's connection is gone, belongs to
 *    another tenant than the result names, or is no longer usable (disabled, or
 *    its protocol unavailable or its settings incomplete), as its locked row
 *    shows; or the inheritance contract, asked again, no longer names the
 *    enforcing tenant whose rule is locked, which is never locked out of order.
 * 2. `enforcement_unsatisfied`: the enforcement of the connection's tenant on the
 *    result's application requires sign-in through connections this one is not among.
 *    Under the default contract it is judged from the locked rows; another contract
 *    bound is asked now, and must itself keep a change to its rule from committing
 *    between its answer and the session's commit (a current read alone is not
 *    enough), or the session escapes the change.
 * 3. the purpose's own rules (`Contracts\PurposeBranch`): `SignInBranch`,
 *    `LinkBranch` or `ReauthenticationBranch`, which compare the link as it is
 *    now with the one observed at completion by its id, so identity equality
 *    alone never hides a link removed and made again.
 *
 * Otherwise it answers `passed`. A refusal is a value; the redeemer refuses its
 * redemption, and keeps its code consumed.
 *
 * `admit()` is `recheck()` followed by the purpose's writes: activating a
 * reservation, creating or confirming a link, or renewing a session's
 * authentication time, and answers an `Admission`. `discardReservation()`
 * removes the reservation of a code refused after it was consumed, by its
 * identity and handoff reference and never merely by the subject, in the same
 * transaction.
 *
 * `acknowledgeSignIn()` records, on the locked connection, that a `sign_in`
 * through it has been redeemed (SSO-4.3), which enforcement needs before it can
 * be turned on. The redeemer calls it after the recheck passed, for a `sign_in`
 * result that resolved to an identity, inside the same transaction, so a
 * redemption rolled back records nothing. A result of another purpose is a
 * `LogicException`: a `link` or a `reauthenticate` never completes a sign-in.
 *
 * A database error and a contract's exception propagate (SSO-11.4). It holds
 * the connection lookup, the drivers' registry, the enforcement contract, the
 * reservations and the container, none of which keeps anything of one
 * redemption for the next (SSO-11.2); resolve it from the container per
 * request.
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
     * @param  \SineMacula\Laravel\Sso\Links\LinkReservations  $reservations
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
        private LinkReservations $reservations,

        /** Resolves the branch of the result's purpose. */
        private Container $container,
    ) {}

    /**
     * Take the locks a redemption through the tenant's connection, for the
     * application, holds before it locks its code: the enforcing tenant's rule,
     * then the connection and the rule's connections, in id order, under the
     * default enforcement contract with the feature on; the connection alone
     * otherwise; then the domain claim of the reservation named, if any.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $application
     * @param  ?string  $reservationId
     * @return \SineMacula\Laravel\Sso\Handoffs\RecheckLock
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function lock(string $tenantId, string $connectionId, string $application, ?string $reservationId = null): RecheckLock
    {
        self::assertInTransaction();

        $enforcement = $this->enforcement instanceof DatabaseEnforcement ? $this->enforcement->lock($tenantId, $application, [$connectionId]) : null;
        $connection  = $enforcement === null ? $this->connections->findForUpdate($tenantId, $connectionId) : $enforcement->connection($tenantId, $connectionId);

        $domain = $connection === null ? null : self::lockedDomain($connectionId, $reservationId);

        return RecheckLock::held($tenantId, $connectionId, $application, $connection, $enforcement, $domain);
    }

    /**
     * Check again, under the lock, that the result's connection is usable and
     * satisfies its tenant's enforcement, and that the result's purpose's rules
     * hold for what the code was bound to.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $binding
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function recheck(VerifiedResult $result, HandoffBinding $binding, RecheckLock $lock, ?IdentityReference $caller = null): RecheckOutcome
    {
        self::assertHeldFor($lock, $result);

        $refusal = $this->refusal($lock);

        if ($refusal !== null || $lock->connection === null) {
            return $refusal ?? RecheckOutcome::CONNECTION_UNAVAILABLE;
        }

        return $this->branch($result)->judge(new RedemptionContext($result, $binding, $lock, $lock->connection, $caller));
    }

    /**
     * Recheck, and make the purpose's writes when it passes, under the lock, in
     * the redeemer's transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $binding
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Admission
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function admit(VerifiedResult $result, HandoffBinding $binding, RecheckLock $lock, ?IdentityReference $caller = null): Admission
    {
        $outcome = $this->recheck($result, $binding, $lock, $caller);

        if ($outcome !== RecheckOutcome::PASSED || $lock->connection === null) {
            return Admission::refused($outcome);
        }

        return $this->branch($result)->admit(new RedemptionContext($result, $binding, $lock, $lock->connection, $caller));
    }

    /**
     * Remove the reservation of a code refused after it was consumed, in the
     * redeemer's transaction; anything but exactly that reservation is left.
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

        $this->reservations->deleteRefused($connectionId, $binding->reservationId, $binding->handoffReference);
    }

    /**
     * Record that a `sign_in` through the result's connection was redeemed, on
     * the connection's locked row.
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
     * Why the redemption is refused before its link is asked about, or `null`:
     * a connection gone or unusable, or an enforcing tenant that moved, is
     * `connection_unavailable`; an enforcement the connection does not satisfy,
     * `enforcement_unsatisfied`.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @return ?\SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     *
     * @throws \InvalidArgumentException
     */
    private function refusal(RecheckLock $lock): ?RecheckOutcome
    {
        $connection = $lock->connection;

        if ($connection === null || !$this->protocols->isUsable($connection)) {
            return RecheckOutcome::CONNECTION_UNAVAILABLE;
        }

        $policy = $this->policy($lock);

        return match (true) {
            $policy === null                         => RecheckOutcome::CONNECTION_UNAVAILABLE,
            !$policy->isSatisfiedBy($connection->id) => RecheckOutcome::ENFORCEMENT_UNSATISFIED,
            default                                  => null,
        };
    }

    /**
     * The enforcement the connection is judged by: from the locked rows when
     * the default contract locked them, `null` when the inheritance contract no
     * longer names the tenant whose rule is locked; asked of the bound contract
     * now otherwise.
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
     * Refuse a call outside a transaction on the storage connection, or under a
     * lock taken for another tenant, connection or application than the
     * result's.
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
     * Refuse a call made out of turn: outside the redeemer's transaction, under
     * another result's lock, for a result that completes no sign-in, or before
     * the recheck.
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
     * The domain claim of the reservation named, locked; `null` when none is
     * named, or the reservation is gone, or its claim is. The reservation is
     * read plainly to find it, since it is locked only after the code; the
     * binding is immutable, and the branch confirms it under the lock.
     *
     * @param  string  $connectionId
     * @param  ?string  $reservationId
     * @return ?\SineMacula\Laravel\Sso\Models\Domain
     */
    private static function lockedDomain(string $connectionId, ?string $reservationId): ?Domain
    {
        if ($reservationId === null) {
            return null;
        }

        $domainId = Link::query()->useWritePdo()
            ->where('reservation_id', $reservationId)
            ->where('connection_id', $connectionId)
            ->value('reservation_domain_id');

        return is_string($domainId) ? Domain::query()->useWritePdo()->lockForUpdate()->whereKey($domainId)->first() : null;
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
