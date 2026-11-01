<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The checks every redemption of a handoff code makes again (SSO-4.6, SSO-8.5,
 * SSO-9.9), and the acknowledgement of a completed sign-in (SSO-4.3): the
 * package's own redemption asks them, and so does an adapter that redeems its
 * own codes (under `laravel-iam`, `laravel-authentication`'s handoff codes,
 * AUTH-3.10), with the verified result its code carries.
 *
 * Each runs only inside a transaction the redeemer has open on the package's
 * storage connection, the one that consumes its code, so the locks, the checks,
 * the consumption, the acknowledgement and the session the redeemer writes
 * commit or roll back together; called with no transaction open there, each
 * throws a `LogicException` (decision D5). A redeemer writing through another
 * connection is not atomic with them.
 *
 * `lock()` comes first, before the redeemer locks its own code, so every
 * redemption takes the package's lock order (`flows.md`): the tenant's
 * enforcement row, then connection rows in id order, then the code. Under the
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
 * 2. `enforcement_unsatisfied`: the enforcement of the connection's tenant on
 *    the result's application requires sign-in through connections this one is
 *    not among. Under the default contract it is judged from the locked rows;
 *    another contract bound is asked now, and must itself keep a change to its
 *    rule from committing between its answer and the session's commit (a
 *    current read alone is not enough), or the session escapes the change.
 * 3. `link_changed`: the bound `Contracts\Linker`, asked now, resolves the
 *    result to another identity than the one given, which the code resolved to
 *    at completion: a link removed or now naming another identity since, or a
 *    link where there was none. Two identities are the same only when their
 *    type and id are equal byte for byte. The package's link store reads the
 *    link with a locking read.
 *
 * Otherwise it answers `passed`. A refusal is a value; the redeemer refuses its
 * redemption, and keeps its code consumed.
 *
 * `acknowledgeSignIn()` records, on the locked connection, that a `sign_in`
 * through it has been redeemed (SSO-4.3), which enforcement needs before it can
 * be turned on. The redeemer calls it after the recheck passed, for a `sign_in`
 * result that resolved to an identity, inside the same transaction, so a
 * redemption rolled back records nothing. A result of another purpose is a
 * `LogicException`: a `link` or a `reauthenticate` never completes a sign-in.
 *
 * A database error and a contract's exception propagate (SSO-11.4). It holds
 * the connection lookup, the drivers' registry and the two contracts, none of
 * which keeps anything of one redemption for the next (SSO-11.2); resolve it
 * from the container per request.
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
     * @param  \SineMacula\Laravel\Sso\Contracts\Linker  $linker
     */
    public function __construct(

        /** Locks the connection, of the tenant, when no enforcement is locked. */
        private ConnectionFinder $connections,

        /** Whether the connection is still usable. */
        private ProtocolManager $protocols,

        /** Locks, or answers, the enforcement of the connection's tenant. */
        private Enforcement $enforcement,

        /** Resolves the identity the result is linked to now. */
        private Linker $linker,
    ) {}

    /**
     * Take the locks a redemption through the tenant's connection, for the
     * application, holds before it locks its code: the enforcing tenant's rule,
     * then the connection and the rule's connections, in id order, under the
     * default enforcement contract with the feature on; the connection alone
     * otherwise.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $application
     * @return \SineMacula\Laravel\Sso\Handoffs\RecheckLock
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function lock(string $tenantId, string $connectionId, string $application): RecheckLock
    {
        self::assertInTransaction();

        $enforcement = $this->enforcement instanceof DatabaseEnforcement ? $this->enforcement->lock($tenantId, $application, [$connectionId]) : null;
        $connection  = $enforcement === null ? $this->connections->findForUpdate($tenantId, $connectionId) : $enforcement->connection($tenantId, $connectionId);

        return RecheckLock::held($tenantId, $connectionId, $application, $connection, $enforcement);
    }

    /**
     * Check again, under the lock, that the result's connection is usable and
     * satisfies its tenant's enforcement, and that its link resolves to the
     * identity given.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $linkedIdentity
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @return \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function recheck(VerifiedResult $result, ?IdentityReference $linkedIdentity, RecheckLock $lock): RecheckOutcome
    {
        self::assertHeldFor($lock, $result);

        return $this->refusal($lock) ?? (self::isSame($linkedIdentity, $this->linker->resolve($result)) ? RecheckOutcome::PASSED : RecheckOutcome::LINK_CHANGED);
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
     * Whether the identity resolved now is the one resolved at completion: both
     * none, or both the same type and id.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $before
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $now
     * @return bool
     */
    private static function isSame(?IdentityReference $before, ?IdentityReference $now): bool
    {
        if ($before === null || $now === null) {
            return $before === $now;
        }

        return $before->is($now);
    }
}
