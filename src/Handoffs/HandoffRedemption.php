<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Sessions\Provenance;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

/**
 * Redeems a handoff code the package's own store issued (SSO-9.2, SSO-9.9,
 * SSO-4.6, SSO-8.5): the client that started the flow presents the code with
 * its verifier, and the application's redemption endpoint asks for the purpose
 * it redeems, the application and the connection.
 *
 * In this fixed order, the first that refuses ending the redemption:
 *
 * 1. the redemption is counted against the IP address of the client it is made
 *    for (none for a client with no IP address) (SSO-11.8); a full limit is
 *    `rate_limited`;
 * 2. a code that is not 43 base64url characters is `handoff_unknown`; a
 *    reference, a verifier or anything else never stands for a code;
 * 3. the stored code is read by its digest on the write connection (SSO-11.3)
 *    and matched again in constant time (SSO-11.9); none is `handoff_unknown`;
 * 4. the code's connection's tenant is read by a plain read (it never changes),
 *    before the transaction, so the guard below is the first thing a standalone
 *    redemption's transaction does; then, in a transaction on the storage
 *    connection (a savepoint inside the caller's), a connection gone is
 *    `connection_unavailable`, and `HandoffRecheck::lock()` takes the locks of
 *    the package's order for that tenant, the connection and the code's
 *    application: for a code bound to a reservation or a `link` code, its
 *    identity's guard (for a `link`, before any read, so what an earlier holder
 *    of the guard committed is seen); under the default enforcement contract
 *    with the feature on, the enforcing tenant's rule (named by the inheritance
 *    contract, its row inserted unconfigured when it has none), then the
 *    connection and the rule's connections in id order; otherwise the
 *    connection alone; for a `link`, the connections holding the identity's
 *    verified domain links with them. A connection gone meanwhile is
 *    `connection_unavailable`. Only then is the code's row read again, locked:
 *    a code gone, or one that no longer names what its plain read did (whose
 *    locks were taken), is `handoff_unknown`. Each read under a lock is a
 *    locking read on the write connection, so a caller's older
 *    `REPEATABLE READ` snapshot never answers;
 * 5. the standalone path asked for any purpose but a `link` is a
 *    `LogicException`, before anything is recorded or consumed; asked for a
 *    `link` with a code of another purpose, it goes on, and step 9 refuses it;
 * 6. a code a change to its connection voided is `handoff_unknown`; a code
 *    redeemed before, or one the single-use store has seen (keyed by its digest
 *    until its expiry, and at least a second), is `replayed`;
 * 7. the code is consumed: its `redeemed_at` is set, in the transaction, so
 *    racing servers consume it exactly once; every later refusal keeps it
 *    consumed;
 * 8. a code whose expiry is not after now is `handoff_expired`;
 * 9. a code of another purpose than the one asked is `purpose_mismatch`, so a
 *    code is redeemed only by the operation of its purpose (SSO-9.9);
 * 10. one of another application, compared exactly, is `application_mismatch`;
 * 11. one of another connection, compared exactly, is `connection_mismatch`;
 * 12. a verifier that is not 43 to 128 unreserved characters, or does not
 *     satisfy the code's S256 challenge (compared in constant time), is
 *     `verifier_mismatch`, so only the client that started the flow redeems it
 *     (SSO-5.2);
 * 13. the verified result is decrypted and restored, and
 *     `Handoffs\HandoffRecheck::admit()` checks the connection, enforcement and
 *     the purpose's own rules again, under the locks of step 4, and makes the
 *     purpose's writes: `connection_unavailable` (the inheritance contract no
 *     longer naming the tenant whose rule is locked included),
 *     `enforcement_unsatisfied`, or the branch's refusal (`link_changed`,
 *     `link_suspended`, `reservation_invalid`, `identity_mismatch` and the
 *     others of `Handoffs\Redemption`); a rule change waits for the
 *     redemption's transaction, the caller's included, and its revocation then
 *     sees the session the caller wrote in it;
 * 14. a `sign_in` that established an identity acknowledges the completed
 *     sign-in on its connection (SSO-4.3), in the same transaction; a `link` or
 *     `reauthenticate` code, an unlinked handoff and a code never redeemed
 *     never do;
 * 15. `HandoffRedeemed` is reported, after commit, with
 *     `ReauthenticationCompleted` for a `reauthenticate`, and `LinkCreated` and
 *     `LinkActivated` before them for an activated reservation;
 * 16. it answers `redeemed`, with the result, the identity it established, the
 *     flow's identity and session, the version of the enforcement step 13
 *     judged under the locks (never the one the completion checked, which a
 *     rule change may since have replaced), the session's latest end, the
 *     link, the evidence accepted, whether it was admitted and,
 *     for a `sign_in` (which is only ever redeemed admitted, step 5), the
 *     session provenance captured here, inside the transaction, from what the
 *     admission established under the locks (`Sessions\Provenance::capture()`,
 *     SSO-9.10); a `link` and a `reauthenticate` capture none.
 *
 * Any refusal after the code was consumed deletes that code's reservation, by
 * its identity and reference, in the same transaction, and queues one failure
 * event; the refusal commits, and the code stays spent. An exception rolls
 * everything back, the consumption and any activation together, and the
 * redemption is then retried only as the caller's whole transaction.
 *
 * `admit()` is the session-admission API: it requires the caller's transaction
 * open on the storage connection, keeps the locks until that commits, and the
 * session the caller writes in it commits or rolls back with the consumption
 * (decision D5). `redeem()` called with such a transaction open is the same.
 * `redeem()` called with none is the standalone path: it commits before it
 * answers, so nothing written afterwards is protected, and its result answers
 * `isAdmitted()` false. It exists for a `link` alone, which writes no session.
 * Asking it for a `sign_in`, linked or unlinked, or a `reauthenticate` is a
 * `LogicException` that leaves the code unconsumed and unrecorded in the
 * single-use store, since each must commit with the session the caller writes:
 * an unlinked handoff is redeemed through `admit()` like any other. A `sign_in`
 * or `reauthenticate` code presented where a `link` is asked for is a client's
 * error, not the caller's: it is consumed and refused as `purpose_mismatch`,
 * like any code of another purpose. A standalone `link` that comes to a
 * verified domain link in a connection it did not lock
 * (`Exceptions\LinkCandidatesChanged`), which taking the guard before any read
 * leaves to an isolation stricter than the default, is rolled back and
 * restarted once, from its transaction; a second time it propagates. Inside a
 * caller's transaction it always propagates, and the caller retries its whole
 * transaction.
 *
 * On PostgreSQL under `REPEATABLE READ`, a redemption that waited on a rule
 * change may fail to serialise instead: the error propagates, never retried in
 * part, and a caller's transaction around it must be retried whole.
 *
 * Every refusal reports exactly one `FlowFailed` (`Flow::REDEMPTION`) with its
 * reason, after the transaction that consumed the code commits, and never when
 * the caller's transaction around it rolls back (SSO-10.5): a redemption inside
 * the caller's transaction is part of it, undone with it, its consumption
 * included (decision D5).
 *
 * A stored result the package did not write (one no JSON decodes to a result,
 * or bound to another purpose, application, connection or reference than its
 * code, or to another tenant than its connection's) is an
 * `UnexpectedValueException`; it, a ciphertext no key decrypts, a database
 * error and a contract's exception propagate as server errors (SSO-11.4), roll
 * the transaction back, and leave the code unconsumed.
 *
 * `admit()` and `redeem()` take the client the redemption is made for as an
 * `Http\ClientContext`, which the application builds where it reads the
 * request; neither reads the request being served itself. It holds the limiter,
 * the store, the encrypter, the recheck, the reporter and the clock, none of
 * which keeps anything of one redemption for the next (SSO-11.2). Resolve it
 * from the container per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class HandoffRedemption
{
    /** @var string The single-use namespace a consumed code is recorded in. */
    public const string NAMESPACE = 'handoff_code';

    /** @var string What a code that must commit with a session reaching the standalone path is. */
    private const string NOT_STANDALONE = 'A [sign_in] or [reauthenticate] code is redeemed through admit(), in the caller\'s transaction (decision D5).';

    /** @var string What a stored result the package did not write is. */
    private const string CORRUPT = 'A handoff code\'s stored result is not one the package wrote.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Sso\Contracts\SingleUseStore  $store
     * @param  \SineMacula\Laravel\Sso\Contracts\SecretEncrypter  $encrypter
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffRecheck  $recheck
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffEvents  $events
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Counts each redemption against the client's IP address. */
        private AttemptLimiter $limiter,

        /** Records each consumed code once. */
        private SingleUseStore $store,

        /** Decrypts the verified result the code carries. */
        private SecretEncrypter $encrypter,

        /** Checks the connection, enforcement and the link again. */
        private HandoffRecheck $recheck,

        /** Reports how the redemption ended. */
        private HandoffEvents $events,

        /** The clock the consumption and the expiry are read from. */
        private Clock $clock,
    ) {}

    /**
     * Redeem the code as the session-admission API, inside the caller's
     * transaction, for the purpose, the application and the connection, for the
     * client, with its verifier and the caller the application has
     * authenticated.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \LogicException
     */
    public function admit(
        Purpose $purpose,
        string $application,
        string $connectionId,
        #[\SensitiveParameter] string $code,
        #[\SensitiveParameter] string $verifier,
        ClientContext $client,
        ?IdentityReference $caller = null,
    ): RedemptionResult {
        if (DB::connection(StorageConnection::name())->transactionLevel() === 0) {
            throw new \LogicException('A session is admitted inside the caller\'s transaction on the package\'s storage connection (decision D5).');
        }

        return $this->redeem($purpose, $application, $connectionId, $code, $verifier, $client, $caller);
    }

    /**
     * Redeem the code, for the purpose, the application and the connection, for
     * the client, with its verifier and the caller the application has
     * authenticated, which a `link` needs: inside the caller's transaction, it
     * is what `admit()` is; with none open, the standalone path of a `link`.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    public function redeem(
        Purpose $purpose,
        string $application,
        string $connectionId,
        #[\SensitiveParameter] string $code,
        #[\SensitiveParameter] string $verifier,
        ClientContext $client,
        ?IdentityReference $caller = null,
    ): RedemptionResult {
        $attempt = $this->limiter->attempt(AttemptSubject::redemption($client));

        if ($attempt->retryAfter !== null) {

            $this->events->refused(FailureReason::RATE_LIMITED, $purpose, $client);

            return RedemptionResult::rateLimited($attempt->retryAfter);
        }

        $found = self::find($code);

        if ($found === null) {

            $this->events->refused(FailureReason::HANDOFF_UNKNOWN, $purpose, $client);

            return RedemptionResult::refused(FailureReason::HANDOFF_UNKNOWN);
        }

        $mismatch = static fn (StoredCode $stored, CarbonImmutable $now): ?FailureReason => self::mismatch($stored, $purpose, $application, $connectionId, $verifier, $now);

        $database = DB::connection(StorageConnection::name());
        $admitted = $database->transactionLevel() > 0;
        $tenantId = Connection::query()->useWritePdo()->whereKey($found->connection_id)->value('tenant_id');
        $tenantId = is_string($tenantId) ? $tenantId : null;
        $attempt  = fn (): RedemptionResult => $database->transaction(
            fn (): RedemptionResult => $this->locked($found, $tenantId, $mismatch, $caller, $admitted, $purpose, $client),
        );

        return $admitted ? $attempt() : self::restartedOnce($attempt);
    }

    /**
     * Run the standalone redemption, and run it once more from its start when
     * it came to a verified domain link in a connection it had not locked: the
     * exception rolled its transaction back whole, the consumption included.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $attempt
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private static function restartedOnce(\Closure $attempt): RedemptionResult
    {
        try {
            return $attempt();
        } catch (LinkCandidatesChanged) {
            return $attempt();
        }
    }

    /**
     * The stored code the value is, read by its digest on the write connection
     * and matched again in constant time, or `null` when the value is not a
     * code or none is stored for it.
     *
     * @param  string  $code
     * @return ?\SineMacula\Laravel\Sso\Models\HandoffCode
     */
    private static function find(#[\SensitiveParameter] string $code): ?StoredCode
    {
        if (!HandoffCode::isWellFormed($code)) {
            return null;
        }

        $handoff = HandoffCode::fromString($code);
        $found   = StoredCode::query()->useWritePdo()->where('code_digest', $handoff->digest())->first();

        return $found !== null && $handoff->matches($found->code_digest) ? $found : null;
    }

    /**
     * In the transaction: take the recheck's locks for the code's connection
     * and application, for the tenant a plain read gave before it (a
     * connection's tenant never changes), a `link` naming the identity it
     * confirms for, and none when the connection was gone; then lock the code,
     * refuse a purpose the standalone path cannot redeem, and consume the code
     * unless it is gone or no longer the code those locks were taken for,
     * judged against the clock once all are locked.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $found
     * @param  ?string  $tenantId
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\HandoffCode, \Carbon\CarbonImmutable): ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $mismatch
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @param  bool  $admitted
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function locked(
        StoredCode $found,
        ?string $tenantId,
        \Closure $mismatch,
        ?IdentityReference $caller,
        bool $admitted,
        Purpose $purpose,
        ClientContext $client,
    ): RedemptionResult {
        $confirming = $found->purpose === Purpose::LINK ? IdentityReference::fromColumns($found->identity_type, $found->identity_id) : null;
        $lock       = $tenantId       === null ? null : $this->recheck->lock($tenantId, $found->connection_id, $found->application, $found->reservation_id, $confirming);

        if ($lock?->connection === null) {
            return $this->refuse(FailureReason::CONNECTION_UNAVAILABLE, $found, $client);
        }

        $connection = $lock->connection;
        $code       = StoredCode::query()->useWritePdo()->lockForUpdate()->whereKey($found->id)->first();

        if (!self::isStill($code, $found)) {
            return $this->refuse(FailureReason::HANDOFF_UNKNOWN, $found, $client, $connection);
        }

        self::assertAdmissible($purpose, $admitted);

        $refusal = match (true) {
            $code->voided_at !== null                   => FailureReason::HANDOFF_UNKNOWN,
            $this->isReplay($code, $this->clock->now()) => FailureReason::REPLAYED,
            default                                     => null,
        };

        return $refusal === null ? $this->consume($code, $lock, $connection, $mismatch, $caller, $admitted, $client) : $this->refuse($refusal, $code, $client, $connection);
    }

    /**
     * Whether the code read locked is still the one found: not gone, and still
     * naming the connection, the application, the reservation and the identity
     * the locks were taken for.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $found
     * @return bool
     *
     * @phpstan-assert-if-true \SineMacula\Laravel\Sso\Models\HandoffCode $code
     */
    private static function isStill(?StoredCode $code, StoredCode $found): bool
    {
        return $code !== null
            && [$code->connection_id, $code->application, $code->reservation_id, $code->identity_type, $code->identity_id]
            === [$found->connection_id, $found->application, $found->reservation_id, $found->identity_type, $found->identity_id];
    }

    /**
     * Consume the code, then refuse what it does not match, deleting its
     * reservation; redeem it otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\HandoffCode, \Carbon\CarbonImmutable): ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $mismatch
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @param  bool  $admitted
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function consume(
        StoredCode $code,
        RecheckLock $lock,
        Connection $connection,
        \Closure $mismatch,
        ?IdentityReference $caller,
        bool $admitted,
        ClientContext $client,
    ): RedemptionResult {
        $now = $this->clock->now();

        $code->forceFill(['redeemed_at' => $now])->save();

        $refusal = $mismatch($code, $now);

        return $refusal === null ? $this->redeemed($code, $lock, $connection, $caller, $admitted, $client) : $this->refuseConsumed($refusal, $code, $connection, $client);
    }

    /**
     * Refuse a purpose the standalone path cannot redeem: any but a `link`,
     * whose session must commit with its consumption. Thrown before the
     * single-use store records the code, or it is consumed. The purpose asked
     * for decides, not the code's: a code of another purpose presented for a
     * `link` is the client's error, refused as `purpose_mismatch` once
     * consumed.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  bool  $admitted
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertAdmissible(Purpose $purpose, bool $admitted): void
    {
        if ($admitted || $purpose === Purpose::LINK) {
            return;
        }

        throw new \LogicException(self::NOT_STANDALONE);
    }

    /**
     * Whether the code was redeemed before, or the single-use store has seen
     * it; otherwise it is recorded there now, until its expiry and at least a
     * second from now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \Throwable
     */
    private function isReplay(StoredCode $code, CarbonImmutable $now): bool
    {
        if ($code->redeemed_at !== null) {
            return true;
        }

        $until = $now->addSecond()->max($code->expires_at);

        return $this->store->record(self::NAMESPACE, $code->code_digest, $until) !== SingleUseOutcome::RECORDED;
    }

    /**
     * Why the consumed code may not be redeemed with what was presented, or
     * `null` when it may: expired, then another purpose, application or
     * connection, then a verifier that does not satisfy its challenge.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $verifier
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function mismatch(
        StoredCode $code,
        Purpose $purpose,
        string $application,
        string $connectionId,
        #[\SensitiveParameter] string $verifier,
        CarbonImmutable $now,
    ): ?FailureReason {
        return match (true) {
            $code->expires_at <= $now              => FailureReason::HANDOFF_EXPIRED,
            $code->purpose       !== $purpose      => FailureReason::PURPOSE_MISMATCH,
            $code->application   !== $application  => FailureReason::APPLICATION_MISMATCH,
            $code->connection_id !== $connectionId => FailureReason::CONNECTION_MISMATCH,
            !self::isVerifiedBy($code, $verifier)  => FailureReason::VERIFIER_MISMATCH,
            default                                => null,
        };
    }

    /**
     * Whether the value is a verifier that satisfies the code's S256 challenge,
     * compared in constant time.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  string  $verifier
     * @return bool
     */
    private static function isVerifiedBy(StoredCode $code, #[\SensitiveParameter] string $verifier): bool
    {
        if (!Verifier::isWellFormed($verifier)) {
            return false;
        }

        return S256Challenge::fromString($code->handoff_challenge)->isSatisfiedBy(Verifier::fromString($verifier));
    }

    /**
     * Restore the code's result, check the connection, enforcement and the
     * purpose's rules again under the locks and make its writes, acknowledge a
     * completed sign-in, report the redemption and answer it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @param  bool  $admitted
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \UnexpectedValueException
     */
    private function redeemed(StoredCode $code, RecheckLock $lock, Connection $connection, ?IdentityReference $caller, bool $admitted, ClientContext $client): RedemptionResult
    {
        $result    = $this->restored($code, $lock);
        $admission = $this->recheck->admit($result, self::binding($code), $lock, $client, $caller);
        $reason    = $admission->outcome->reason();

        if ($reason !== null) {
            return $this->refuseConsumed($reason, $code, $connection, $client);
        }

        if ($code->purpose === Purpose::SIGN_IN && $admission->identity !== null) {
            $this->recheck->acknowledgeSignIn($result, $lock);
        }

        $this->events->redeemed($code, $connection, $client, $admission->identity);

        return RedemptionResult::redeemed(
            result: $result,
            linkedIdentity: $admission->identity,
            identity: IdentityReference::fromColumns($code->identity_type, $code->identity_id),
            sessionId: $code->session_id,
            enforcementVersion: $admission->enforcementVersion,
            sessionNotAfter: $code->session_not_after,
            linkId: $admission->linkId,
            evidence: $admission->evidence,
            admitted: $admitted,
            provenance: Provenance::capture($result, $admission, $code->session_not_after),
        );
    }

    /**
     * What the stored code was bound to.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @return \SineMacula\Laravel\Sso\Handoffs\HandoffBinding
     *
     * @throws \InvalidArgumentException
     */
    private static function binding(StoredCode $code): HandoffBinding
    {
        return new HandoffBinding(
            IdentityReference::fromColumns($code->linked_identity_type, $code->linked_identity_id),
            $code->link_id,
            IdentityReference::fromColumns($code->identity_type, $code->identity_id),
            $code->session_id,
            $code->reservation_id,
            $code->id,
            $code->trust_version,
        );
    }

    /**
     * The verified result the code carries, decrypted and restored, and bound
     * to the code's purpose, application, connection and reference, and to the
     * connection's tenant the locks were taken for.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \RuntimeException
     * @throws \UnexpectedValueException
     */
    private function restored(StoredCode $code, RecheckLock $lock): VerifiedResult
    {
        $stored = json_decode($this->encrypter->decrypt($code->result), true);
        $result = is_array($stored) ? VerifiedResult::restore($stored) : self::corrupt();

        return self::isBoundTo($result, $code) && $lock->isFor($result) ? $result : self::corrupt();
    }

    /**
     * Refuse to go on with a stored result the package did not write.
     *
     * @return never
     *
     * @throws \UnexpectedValueException
     */
    private static function corrupt(): never
    {
        throw new \UnexpectedValueException(self::CORRUPT);
    }

    /**
     * Whether the result names the code's purpose, application, connection and
     * request reference, exactly.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @return bool
     */
    private static function isBoundTo(VerifiedResult $result, StoredCode $code): bool
    {
        $named = [$result->purpose, $result->application, $result->connectionId, $result->requestReference->value];

        return $named === [$code->purpose, $code->application, $code->connection_id, $code->request_reference];
    }

    /**
     * Report a redemption of the stored code refused for the reason, and answer
     * it.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \InvalidArgumentException
     */
    private function refuse(FailureReason $reason, StoredCode $code, ClientContext $client, ?Connection $connection = null): RedemptionResult
    {
        $this->events->failed($reason, $code, $client, $connection);

        return RedemptionResult::refused($reason);
    }

    /**
     * Refuse a code consumed, deleting its reservation in the same transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function refuseConsumed(FailureReason $reason, StoredCode $code, Connection $connection, ClientContext $client): RedemptionResult
    {
        $this->recheck->discardReservation(self::binding($code), $connection->id);

        return $this->refuse($reason, $code, $client, $connection);
    }
}
