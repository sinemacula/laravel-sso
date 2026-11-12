<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Database\RetriedTransaction;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Sessions\Provenance;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

/**
 * Redeems a handoff code the package's own store issued.
 *
 * admit() runs inside the caller's transaction on the storage connection;
 * redeem() with no transaction open redeems only a `link`.
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

    /** @var int Most times the standalone transaction is tried. */
    private const int ATTEMPTS = 3;

    /** @var string Thrown when the standalone path is asked for a session. */
    private const string NOT_STANDALONE = 'A [sign_in] or [reauthenticate] code is redeemed through admit(), in the caller\'s transaction.';

    /** @var string Thrown for a stored result the package did not write. */
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
     * Redeem the code inside the caller's transaction, so the session commits
     * with the consumption.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
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
        ?Caller $caller = null,
    ): RedemptionResult {
        if (DB::connection(StorageConnection::name())->transactionLevel() === 0) {
            throw new \LogicException('A session is admitted inside the caller\'s transaction on the package\'s storage connection.');
        }

        return $this->redeem($purpose, $application, $connectionId, $code, $verifier, $client, $caller);
    }

    /**
     * Redeem the code; with no transaction open, only a `link` is redeemable.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
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
        ?Caller $caller = null,
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
        $attempt  = fn (): RedemptionResult => RetriedTransaction::run(
            $database,
            fn (): RedemptionResult => $this->locked($found, $tenantId, $mismatch, $caller, $admitted, $purpose, $client),
            self::ATTEMPTS,
        );

        return $admitted ? $attempt() : self::restartedOnce($attempt);
    }

    /**
     * Run the standalone redemption again once if its link candidates changed.
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
     * Find the stored code by digest and match it again in constant time.
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
     * Take the recheck's locks, then lock the code and consume it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $found
     * @param  ?string  $tenantId
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\HandoffCode, \Carbon\CarbonImmutable): ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $mismatch
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  bool  $admitted
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function locked(StoredCode $found, ?string $tenantId, \Closure $mismatch, ?Caller $caller, bool $admitted, Purpose $purpose, ClientContext $client): RedemptionResult
    {
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
     * Whether the locked code still names what its locks were taken for.
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
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
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
        ?Caller $caller,
        bool $admitted,
        ClientContext $client,
    ): RedemptionResult {
        $now = $this->clock->now();

        $code->forceFill(['redeemed_at' => $now])->save();

        $refusal = $mismatch($code, $now);

        return $refusal === null ? $this->redeemed($code, $lock, $connection, $caller, $admitted, $client) : $this->refuseConsumed($refusal, $code, $connection, $client);
    }

    /**
     * Refuse any purpose but `link` on the standalone path, before the code is
     * recorded or consumed.
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
     * Whether the code was redeemed or seen before; records it otherwise.
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
     * Why the consumed code may not be redeemed, or `null` when it may.
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
     * Whether the value is a verifier that satisfies the code's challenge.
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
     * Recheck the code's result under the locks and answer the redemption.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  bool  $admitted
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \UnexpectedValueException
     */
    private function redeemed(StoredCode $code, RecheckLock $lock, Connection $connection, ?Caller $caller, bool $admitted, ClientContext $client): RedemptionResult
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
     * Decrypt and restore the code's result, checking it is bound to the code.
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
     * Whether the result names exactly the code's purpose, application,
     * connection and reference.
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
     * Report the refusal and answer it.
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
