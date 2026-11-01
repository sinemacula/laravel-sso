<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Applications\ApplicationGate;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionStep;
use SineMacula\Laravel\Sso\Completion\Stages\CheckEnforcement;
use SineMacula\Laravel\Sso\Completion\Stages\ConsumeRequest;
use SineMacula\Laravel\Sso\Completion\Stages\CorrelateResponse;
use SineMacula\Laravel\Sso\Completion\Stages\DecideUnlinked;
use SineMacula\Laravel\Sso\Completion\Stages\DomainReservation;
use SineMacula\Laravel\Sso\Completion\Stages\IssueHandoff;
use SineMacula\Laravel\Sso\Completion\Stages\Provisioning;
use SineMacula\Laravel\Sso\Completion\Stages\ResolveLink;
use SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * Runs a completion's steps in `Enums\CompletionStep`'s fixed order (SSO-5.6,
 * SSO-8.6), each through the stage registered for it (`stageClass()`), and
 * answers how the completion ended (SSO-5.7).
 *
 * 1. Correlation, consumption and validation run outside any transaction the
 *    pipeline opens: the consumption opens its own, so the request is consumed
 *    whether the response then passes or fails, and the validation may fetch.
 * 2. Once a request is consumed, one transaction on the storage connection
 *    locks the connection's row, then the request's row, each with a locking
 *    read on the write connection (SSO-11.3), so neither answers from an older
 *    snapshot. A completion still going on is refused with
 *    `connection_unavailable` when the connection is gone or no longer usable
 *    (`Protocols\ProtocolManager::isUsable()`), or when the request is gone or
 *    a change to its connection voided it since it was consumed; otherwise
 *    every locked step runs, in order, in that transaction.
 * 3. The request's `completed_at` is set in that same transaction, whether the
 *    completion completed or was refused, and the completion is reported
 *    (`Completion\CompletionEvents`), so its events reach listeners once that
 *    commits and never on a rollback (SSO-10.5).
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
 * registry, the application gate, the clock and the reporter, none of which
 * keeps anything of one completion for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CompletionPipeline
{
    /** @var string What a consumed completion that holds no request means. */
    private const string NO_REQUEST = 'A consumed completion holds its request.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Applications\ApplicationGate  $gate
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionEvents  $events
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
    ) {}

    /**
     * The stage registered for the step.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\Enums\CompletionStep  $step
     * @return class-string<\SineMacula\Laravel\Sso\Contracts\CompletionStage>
     */
    public static function stageClass(CompletionStep $step): string
    {
        return match ($step) {
            CompletionStep::CORRELATION        => CorrelateResponse::class,
            CompletionStep::CONSUMPTION        => ConsumeRequest::class,
            CompletionStep::VALIDATION         => ValidateResponse::class,
            CompletionStep::LINK_RESOLUTION    => ResolveLink::class,
            CompletionStep::ENFORCEMENT        => CheckEnforcement::class,
            CompletionStep::DOMAIN_RESERVATION => DomainReservation::class,
            CompletionStep::PROVISIONING       => Provisioning::class,
            CompletionStep::UNLINKED_DECISION  => DecideUnlinked::class,
            CompletionStep::HANDOFF_ISSUANCE   => IssueHandoff::class,
        };
    }

    /**
     * Run the completion of the flow from the state it arrived in, its
     * connection read, and answer how it ended.
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
     * refuses.
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

            $outcome = $this->stage($step)->run($outcome->state);

            if ($outcome->isRefused()) {
                return $outcome;
            }
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
     * In the transaction: lock the connection's row and the request's, run the
     * locked steps of a completion still going on, mark the request completed,
     * report the completion and answer it.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Completion\StageOutcome  $outcome
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \Throwable
     */
    private function finish(Flow $flow, StageOutcome $outcome): CompletionResult
    {
        $state      = $outcome->state;
        $connection = self::lockedConnection($state);
        $request    = self::lockedRequest($state);

        if ($outcome->isProceeding()) {
            $outcome = $this->locked($state, $connection, $request);
        }

        $request?->forceFill(['completed_at' => $this->clock->now()])->save();

        $this->events->report($flow, $outcome);

        return $this->answer($outcome);
    }

    /**
     * Refuse a connection gone or no longer usable, and a request gone or
     * voided, since consumption; run the locked steps otherwise, on the rows as
     * locked.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    private function locked(CompletionState $state, ?Connection $connection, ?AuthorizationRequest $request): StageOutcome
    {
        if ($connection === null || !$this->protocols->isUsable($connection)) {
            return StageOutcome::refuse($state, FailureReason::CONNECTION_UNAVAILABLE);
        }

        if ($request === null || $request->voided_at !== null) {
            return StageOutcome::refuse($state, FailureReason::CONNECTION_UNAVAILABLE);
        }

        $consumed    = $state->consumed    ?? throw new \LogicException(self::NO_REQUEST);
        $application = $state->application ?? throw new \LogicException('A consumed completion holds its application.');

        return $this->steps($state->withConnection($connection)->withAuthorizationRequest($request, $consumed, $application), true);
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
        $application = $state->application          ?? throw new \LogicException('A consumed completion holds its application.');
        $request     = $state->authorizationRequest ?? throw new \LogicException(self::NO_REQUEST);
        $connection  = $state->connection           ?? throw new \LogicException('A consumed completion holds its connection.');
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
        $connection = $state->connection ?? throw new \LogicException('A consumed completion holds its connection.');

        return Connection::query()->useWritePdo()->lockForUpdate()->whereKey($connection->id)->first();
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
