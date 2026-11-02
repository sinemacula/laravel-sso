<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\ApplicationGate;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionStep;
use SineMacula\Laravel\Sso\Completion\Stages\CheckEnforcement;
use SineMacula\Laravel\Sso\Completion\Stages\ConsumeRequest;
use SineMacula\Laravel\Sso\Completion\Stages\CorrelateResponse;
use SineMacula\Laravel\Sso\Completion\Stages\DecideUnlinked;
use SineMacula\Laravel\Sso\Completion\Stages\DomainReservation;
use SineMacula\Laravel\Sso\Completion\Stages\IssueHandoff;
use SineMacula\Laravel\Sso\Completion\Stages\Provisioning;
use SineMacula\Laravel\Sso\Completion\Stages\RecordReplay;
use SineMacula\Laravel\Sso\Completion\Stages\ResolveLink;
use SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\LockedEnforcement;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Metadata\TransitionReceipts;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;

/**
 * Runs a completion's steps in `Enums\CompletionStep`'s fixed order (SSO-5.6,
 * SSO-8.6), each through the stage registered for it (`stageClass()`), and
 * answers how the completion ended (SSO-5.7).
 *
 * 1. Correlation, consumption and validation run outside any transaction the
 *    pipeline opens: the consumption opens its own, so the request is consumed
 *    whether the response then passes or fails, and the validation may fetch.
 * 2. Once a request is consumed, one transaction on the storage connection
 *    takes the package's lock order (`flows.md`). For a completion still going
 *    on, under the default `Contracts\Enforcement` with the `enforcement`
 *    feature on, it first locks the enforcing tenant's rule (the tenant the
 *    inheritance contract names; its row inserted unconfigured when it has
 *    none) and then, in one statement in id order, the connection and the
 *    connections the rule names (`DatabaseEnforcement::lock()`); otherwise, and
 *    for a completion already refused, the connection's row alone. Then the
 *    request's row. Each is a locking read on the write connection (SSO-11.3),
 *    so none answers from an older snapshot. A completion still going on is
 *    refused with `connection_unavailable` when the connection is gone or no
 *    longer usable (`Protocols\ProtocolManager::isUsable()`), when the request
 *    is gone, a change to its connection voided it since it was consumed or the
 *    trust version it was started with is no longer the locked connection's
 *    (unless the response's own key refetch made exactly that change, and its
 *    `Protocols\TransitionReceipt` says so: `Metadata\TransitionReceipts`), or
 *    when the inheritance contract, asked again, no longer names the tenant
 *    whose rule is locked; it is refused with `metadata_expired` when what a
 *    metadata refresh applied to the locked connection has expired by now
 *    (`Metadata\MetadataExpiry`), so metadata that lapses while the response is
 *    validated is never used; otherwise the policy judged from the locked rows
 *    goes on with the state, for the enforcement step, and every locked step
 *    runs, in order, in that transaction. A change to the rule waits for it,
 *    and its revocation then sees the session the handoff leads to only once
 *    that is redeemed; the redemption locks the rule again. On PostgreSQL under
 *    `REPEATABLE READ`, a completion that waited on a change may fail to
 *    serialise instead: the error propagates as a server error.
 * 3. The request's `completed_at` is set in that same transaction, whether the
 *    completion completed or was refused, and the completion is reported
 *    (`Completion\CompletionEvents`), so its events reach listeners once that
 *    commits and never on a rollback (SSO-10.5).
 *
 * An unsolicited SAML response is handed to re-initiation by the correlation
 * step (`StageOutcome::reinitiate()`, SSO-5.8): no further step runs, no
 * request is consumed, and `Completion\UnsolicitedReinitiation` answers it,
 * recording its assertion through the stage registered for `replay_recording`
 * under the connection's lock alone. Any other step handing a completion to
 * re-initiation is a misconfiguration, a `LogicException`.
 *
 * The first stage that refuses ends the completion. A refusal with a trusted
 * redirect target (the request was consumed, its application is registered and
 * its connection read) is `failed`, to the application's exact redirect URI
 * through that connection (`Applications\ApplicationGate::redirectUri()`), with
 * the application's delivery and the request's public reference; one without is
 * `rejected`, a 400, and is reported at once. A completion that ran every step
 * is `completed`, with the issued handoff.
 *
 * A database error, a stage's or a contract's exception (a handoff issuer that
 * cannot issue, a misconfigured redirect URI resolver) propagates and is never
 * answered as `failed` or `rejected` (SSO-11.4); thrown inside the transaction,
 * it rolls the completion back, so no code is kept, nothing is reported and
 * `completed_at` stays unset.
 *
 * Each stage is resolved from the container per completion, so an application
 * or a test may bind its own for a step. It holds the container, the drivers'
 * registry, the application gate, the clock, the reporter, the enforcement
 * contract, the re-initiation and the metadata expiry, none of which keeps
 * anything of one completion for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CompletionPipeline
{
    /** @var array<string, class-string<\SineMacula\Laravel\Sso\Contracts\CompletionStage>> The stage registered for each step, by the step's value. */
    private const array STAGES = [
        'correlation'        => CorrelateResponse::class,
        'consumption'        => ConsumeRequest::class,
        'validation'         => ValidateResponse::class,
        'replay_recording'   => RecordReplay::class,
        'link_resolution'    => ResolveLink::class,
        'enforcement'        => CheckEnforcement::class,
        'domain_reservation' => DomainReservation::class,
        'provisioning'       => Provisioning::class,
        'unlinked_decision'  => DecideUnlinked::class,
        'handoff_issuance'   => IssueHandoff::class,
    ];

    /** @var string What a consumed completion that holds no request means. */
    private const string NO_REQUEST = 'A consumed completion holds its request.';

    /** @var string What a consumed completion that holds no application means. */
    private const string NO_APPLICATION = 'A consumed completion holds its application.';

    /** @var string What a consumed completion that holds no connection means. */
    private const string NO_CONNECTION = 'A consumed completion holds its connection.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Applications\ApplicationGate  $gate
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionEvents  $events
     * @param  \SineMacula\Laravel\Sso\Contracts\Enforcement  $enforcement
     * @param  \SineMacula\Laravel\Sso\Completion\UnsolicitedReinitiation  $reinitiation
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataExpiry  $metadata
     */
    public function __construct(

        /** The container each stage is resolved from, per completion. */
        private Container $container,

        /** Whether the connection is still usable under its lock. */
        private ProtocolManager $protocols,

        /** The application's exact redirect URI. */
        private ApplicationGate $gate,

        /** The clock `completed_at` is read from. */
        private Clock $clock,

        /** Reports how the completion ended. */
        private CompletionEvents $events,

        /** Locks the enforcement of the connection's tenant, when it is the default. */
        private Enforcement $enforcement,

        /** Answers an unsolicited response the correlation step handed over. */
        private UnsolicitedReinitiation $reinitiation,

        /** Whether what was fetched for the locked connection has expired. */
        private MetadataExpiry $metadata,
    ) {}

    /**
     * The stage registered for the step.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\Enums\CompletionStep  $step
     * @return class-string<\SineMacula\Laravel\Sso\Contracts\CompletionStage>
     */
    public static function stageClass(CompletionStep $step): string
    {
        return self::STAGES[$step->value];
    }

    /**
     * Run the completion of the flow from the state it arrived in, its
     * connection read, and answer how it ended: through re-initiation for an
     * unsolicited response the correlation step handed over.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function run(Flow $flow, CompletionState $state): CompletionResult
    {
        $outcome = $this->steps($state, false);

        if ($outcome->isReinitiating()) {
            return $this->reinitiation->run($flow, $outcome->state, $this->stage(CompletionStep::REPLAY_RECORDING));
        }

        if (!$outcome->state->hasRedirectTarget()) {

            $this->events->report($flow, $outcome);

            return self::rejected($outcome);
        }

        return DB::connection(StorageConnection::name())->transaction(fn (): CompletionResult => $this->finish($flow, $outcome));
    }

    /**
     * The rejection of a completion refused before it consumed a request.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\StageOutcome  $outcome
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \LogicException
     */
    private static function rejected(StageOutcome $outcome): CompletionResult
    {
        return CompletionResult::rejected($outcome->reason ?? throw new \LogicException('A completion that consumed no request goes no further.'));
    }

    /**
     * Run the steps that are locked, or those that are not, in order, until one
     * refuses or the correlation step hands the completion to re-initiation.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  bool  $locked
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    private function steps(CompletionState $state, bool $locked): StageOutcome
    {
        $outcome = StageOutcome::proceed($state);

        foreach (CompletionStep::cases() as $step) {

            if ($step->isLocked() !== $locked) {
                continue;
            }

            $outcome = self::handedOver($step, $this->stage($step)->run($outcome->state));

            if (!$outcome->isProceeding()) {
                return $outcome;
            }
        }

        return $outcome;
    }

    /**
     * What the step's stage answered, once it is known that only the
     * correlation step hands a completion to re-initiation.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\Enums\CompletionStep  $step
     * @param  \SineMacula\Laravel\Sso\Completion\StageOutcome  $outcome
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    private static function handedOver(CompletionStep $step, StageOutcome $outcome): StageOutcome
    {
        if ($outcome->isReinitiating() && $step !== CompletionStep::CORRELATION) {
            throw new \LogicException(sprintf('Only the correlation step hands a completion to re-initiation, not the [%s] step.', $step->value));
        }

        return $outcome;
    }

    /**
     * The stage registered for the step, resolved from the container.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\Enums\CompletionStep  $step
     * @return \SineMacula\Laravel\Sso\Contracts\CompletionStage
     *
     * @throws \LogicException
     */
    private function stage(CompletionStep $step): CompletionStage
    {
        $stage = $this->container->make(self::stageClass($step));

        if (!$stage instanceof CompletionStage) {
            throw new \LogicException(sprintf('The [%s] step resolved to %s, which is not a completion stage.', $step->value, get_debug_type($stage)));
        }

        return $stage;
    }

    /**
     * In the transaction: lock the enforcement of a completion still going on
     * and its connections, or else the connection's row, then the request's;
     * run the locked steps of a completion still going on, mark the request
     * completed, report the completion and answer it.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Completion\StageOutcome  $outcome
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \Throwable
     */
    private function finish(Flow $flow, StageOutcome $outcome): CompletionResult
    {
        $state       = $outcome->state;
        $enforcement = $outcome->isProceeding() ? $this->lockedEnforcement($state) : null;
        $connection  = $enforcement === null ? self::lockedConnection($state) : self::lockedWith($enforcement, $state);
        $request     = self::lockedRequest($state);

        if ($outcome->isProceeding()) {
            $outcome = $this->locked($state, $connection, $request, $enforcement);
        }

        $request?->forceFill(['completed_at' => $this->clock->now()])->save();

        $this->events->report($flow, $outcome);

        return $this->answer($outcome);
    }

    /**
     * Refuse a connection gone or no longer usable, a request gone or voided,
     * since consumption, and an enforcing tenant that moved since its rule was
     * locked, then a connection whose fetched metadata has expired; run the
     * locked steps otherwise, on the rows as locked, with the policy the locked
     * rule gives.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\LockedEnforcement  $enforcement
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    private function locked(CompletionState $state, ?Connection $connection, ?AuthorizationRequest $request, ?LockedEnforcement $enforcement): StageOutcome
    {
        if (!$this->isGoingOn($connection, $request, $enforcement, $state->transitionReceipt)) {
            return StageOutcome::refuse($state, FailureReason::CONNECTION_UNAVAILABLE);
        }

        if ($this->metadata->isExpired($connection)) {
            return StageOutcome::refuse($state, FailureReason::METADATA_EXPIRED);
        }

        $consumed    = $state->consumed    ?? throw new \LogicException(self::NO_REQUEST);
        $application = $state->application ?? throw new \LogicException(self::NO_APPLICATION);
        $locked      = $state->withConnection($connection)->withAuthorizationRequest($request, $consumed, $application);

        return $this->steps($enforcement === null ? $locked : $locked->withEnforcementPolicy($enforcement->policy()), true);
    }

    /**
     * Whether the completion may go on under its locks: the connection still
     * there and usable, the request still there, not voided and of the
     * connection's trust version, or across exactly the transition the receipt
     * names, and the locked rule, if any, still the enforcing tenant's.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\LockedEnforcement  $enforcement
     * @param  ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     * @return bool
     *
     * @phpstan-assert-if-true !null $connection
     * @phpstan-assert-if-true !null $request
     */
    private function isGoingOn(?Connection $connection, ?AuthorizationRequest $request, ?LockedEnforcement $enforcement, ?TransitionReceipt $receipt): bool
    {
        $usable = $connection !== null && $this->protocols->isUsable($connection);
        $live   = $connection !== null && $request !== null && self::isLive($connection, $request, $receipt);

        return $usable && $live && ($enforcement?->isCurrent() ?? true);
    }

    /**
     * Whether the locked request is not voided and is of the locked
     * connection's trust version, or crosses exactly the transition the receipt
     * names.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     * @return bool
     */
    private static function isLive(Connection $connection, AuthorizationRequest $request, ?TransitionReceipt $receipt): bool
    {
        if ($request->voided_at !== null) {
            return false;
        }

        return $request->trust_version === $connection->trust_version || TransitionReceipts::permits($receipt, $connection, $request);
    }

    /**
     * The enforcement of the connection's tenant on the request's application,
     * locked with the connection, under the default contract with the feature
     * on; `null`, with nothing locked or asked, otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return ?\SineMacula\Laravel\Sso\Enforcement\LockedEnforcement
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function lockedEnforcement(CompletionState $state): ?LockedEnforcement
    {
        if (!$this->enforcement instanceof DatabaseEnforcement) {
            return null;
        }

        $connection = self::connectionOf($state);

        return $this->enforcement->lock($connection->tenant_id, self::applicationOf($state)->name, [$connection->id]);
    }

    /**
     * The connection's row as the enforcement's lock locked it, or `null` when
     * it is gone.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\LockedEnforcement  $enforcement
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \LogicException
     */
    private static function lockedWith(LockedEnforcement $enforcement, CompletionState $state): ?Connection
    {
        $connection = self::connectionOf($state);

        return $enforcement->connection($connection->tenant_id, $connection->id);
    }

    /**
     * The completion's answer once it has consumed its request: `failed` to the
     * application's redirect URI when refused, `completed` with the handoff
     * otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\StageOutcome  $outcome
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \LogicException
     */
    private function answer(StageOutcome $outcome): CompletionResult
    {
        $state       = $outcome->state;
        $application = self::applicationOf($state);
        $request     = $state->authorizationRequest ?? throw new \LogicException(self::NO_REQUEST);
        $connection  = self::connectionOf($state);
        $redirectUri = $this->gate->redirectUri($application, $connection);
        $reference   = RequestReference::fromString($request->reference);

        if ($outcome->reason !== null) {
            return CompletionResult::failed($outcome->reason, $redirectUri, $application->delivery, $reference);
        }

        $handoff = $state->handoff ?? throw new \LogicException('A completion that ran every step holds its handoff.');

        return CompletionResult::completed($redirectUri, $application->delivery, $reference, $handoff);
    }

    /**
     * The connection's row, locked for update on the write connection, or
     * `null` when it is gone.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \LogicException
     */
    private static function lockedConnection(CompletionState $state): ?Connection
    {
        $connection = self::connectionOf($state);

        return Connection::query()->useWritePdo()->lockForUpdate()->whereKey($connection->id)->first();
    }

    /**
     * The connection a consumed completion holds.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \LogicException
     */
    private static function connectionOf(CompletionState $state): Connection
    {
        return $state->connection ?? throw new \LogicException(self::NO_CONNECTION);
    }

    /**
     * The registered application a consumed completion holds.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Applications\Application
     *
     * @throws \LogicException
     */
    private static function applicationOf(CompletionState $state): Application
    {
        return $state->application ?? throw new \LogicException(self::NO_APPLICATION);
    }

    /**
     * The request's row, locked for update on the write connection, or `null`
     * when it is gone.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return ?\SineMacula\Laravel\Sso\Models\AuthorizationRequest
     *
     * @throws \LogicException
     */
    private static function lockedRequest(CompletionState $state): ?AuthorizationRequest
    {
        $request = $state->authorizationRequest ?? throw new \LogicException(self::NO_REQUEST);

        return AuthorizationRequest::query()->useWritePdo()->lockForUpdate()->whereKey($request->id)->first();
    }
}
