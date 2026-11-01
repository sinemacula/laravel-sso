<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The checks every redemption of a handoff code makes again (SSO-4.6, SSO-8.5,
 * SSO-9.9), and the acknowledgement of a completed sign-in (SSO-4.3): the
 * package's own redemption asks them, and so does an adapter that redeems its
 * own codes (under `laravel-iam`, `laravel-authentication`'s handoff codes,
 * AUTH-3.10), with the verified result its code carries.
 *
 * Both run only inside a transaction the redeemer has open on the package's
 * storage connection, the one that consumes its code, so the checks, the
 * consumption and the acknowledgement commit or roll back together; called with
 * no transaction open there, each throws a `LogicException` (decision D5). A
 * redeemer writing through another connection is not atomic with them.
 *
 * `recheck()` answers, in this order, the first that refuses:
 *
 * 1. `connection_unavailable`: the result's connection is gone, belongs to
 *    another tenant than the result names, or is no longer usable (disabled, or
 *    its protocol unavailable or its settings incomplete). Its row is read with
 *    a locking read on the write connection, held until the redeemer's
 *    transaction ends, so a disable, a trust change or a deletion waits for the
 *    redemption, and a caller's older `REPEATABLE READ` snapshot never answers.
 * 2. `enforcement_unsatisfied`: the bound `Contracts\Enforcement`, asked now
 *    for the connection's tenant on the result's application, requires sign-in
 *    through connections this one is not among. The tenant's enforcement row is
 *    not locked here, since its lock precedes the connection's (the lock order
 *    of `flows.md`); the default contract reads it from the write connection,
 *    which, inside a transaction that has made no plain read yet, is the state
 *    as committed now.
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
 * `acknowledgeSignIn()` records, on the result's connection, that a `sign_in`
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

        /** Locks the result's connection, of the result's tenant. */
        private ConnectionFinder $connections,

        /** Whether the connection is still usable. */
        private ProtocolManager $protocols,

        /** Answers the enforcement of the connection's tenant. */
        private Enforcement $enforcement,

        /** Resolves the identity the result is linked to now. */
        private Linker $linker,
    ) {}

    /**
     * Check again that the result's connection is usable and satisfies its
     * tenant's enforcement, and that its link resolves to the identity given.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $linkedIdentity
     * @return \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function recheck(VerifiedResult $result, ?IdentityReference $linkedIdentity): RecheckOutcome
    {
        $connection = $this->lockedConnection($result);

        if ($connection === null || !$this->protocols->isUsable($connection)) {
            return RecheckOutcome::CONNECTION_UNAVAILABLE;
        }

        if (!$this->enforcement->policy($connection->tenant_id, $result->application)->isSatisfiedBy($connection->id)) {
            return RecheckOutcome::ENFORCEMENT_UNSATISFIED;
        }

        return self::isSame($linkedIdentity, $this->linker->resolve($result)) ? RecheckOutcome::PASSED : RecheckOutcome::LINK_CHANGED;
    }

    /**
     * Record that a `sign_in` through the result's connection was redeemed.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function acknowledgeSignIn(VerifiedResult $result): void
    {
        if ($result->purpose !== Purpose::SIGN_IN) {
            self::outOfTurn(sprintf('Only a [sign_in] result completes a sign-in, not a [%s] one.', $result->purpose->value));
        }

        $connection = $this->lockedConnection($result) ?? self::outOfTurn('The connection a sign-in is acknowledged through is gone: recheck the handoff first.');

        if ($connection->has_completed_sign_in) {
            return;
        }

        $connection->forceFill(['has_completed_sign_in' => true])->save();
    }

    /**
     * The result's connection, of the result's tenant, locked for update on the
     * write connection until the redeemer's transaction ends, or `null` when it
     * is gone.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function lockedConnection(VerifiedResult $result): ?Connection
    {
        if (DB::connection(StorageConnection::name())->transactionLevel() === 0) {
            self::outOfTurn('A handoff is rechecked inside the redeemer\'s transaction on the package\'s storage connection (decision D5).');
        }

        return $this->connections->findForUpdate($result->tenantId, $result->connectionId);
    }

    /**
     * Refuse a call made out of turn: outside the redeemer's transaction, for a
     * result that completes no sign-in, or before the recheck.
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
