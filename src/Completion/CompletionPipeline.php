<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Applications\ApplicationGate;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionStep;
use SineMacula\Laravel\Sso\Completion\Stages\CheckEnforcement;
use SineMacula\Laravel\Sso\Completion\Stages\CheckPurpose;
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
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Linking\LinkingDiscovery;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;

/**
 * Runs a completion's steps in order, across its transactions, and answers how
 * it ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CompletionPipeline
{
    /** @var array<string, class-string<\SineMacula\Laravel\Sso\Contracts\CompletionStage>> The stage for each step, by value. */
    private const array STAGES = [
        'correlation'        => CorrelateResponse::class,
        'consumption'        => ConsumeRequest::class,
        'validation'         => ValidateResponse::class,
        'replay_recording'   => RecordReplay::class,
        'link_resolution'    => ResolveLink::class,
        'enforcement'        => CheckEnforcement::class,
        'purpose_rules'      => CheckPurpose::class,
        'domain_reservation' => DomainReservation::class,
        'provisioning'       => Provisioning::class,
        'unlinked_decision'  => DecideUnlinked::class,
        'handoff_issuance'   => IssueHandoff::class,
    ];

    /** @var string Thrown when a consumed completion holds no request. */
    private const string NO_REQUEST = 'A consumed completion holds its request.';

    /** @var string Thrown when a consumed completion holds no application. */
    private const string NO_APPLICATION = 'A consumed completion holds its application.';

    /** @var string Thrown when a consumed completion holds no connection. */
    private const string NO_CONNECTION = 'A consumed completion holds its connection.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Sso\Applications\ApplicationGate  $gate
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionEvents  $events
     * @param  \SineMacula\Laravel\Sso\Completion\UnsolicitedReinitiation  $reinitiation
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionLocks  $locks
     * @param  \SineMacula\Laravel\Sso\Links\LinkStorageBinding  $storage
     * @param  \SineMacula\Laravel\Sso\Completion\ProvisioningOffer  $offer
     */
    public function __construct(

        /** The container each stage is resolved from, per completion. */
        private Container $container,

        /** The application's exact redirect URI. */
        private ApplicationGate $gate,

        /** The clock `completed_at` is read from. */
        private Clock $clock,

        /** Reports how the completion ended. */
        private CompletionEvents $events,

        /** Answers an unsolicited response the correlation step handed over. */
        private UnsolicitedReinitiation $reinitiation,

        /** Takes the completion's locks and judges what it may do under them. */
        private CompletionLocks $locks,

        /** Discards a reservation a completion made before it refused. */
        private LinkStorageBinding $storage,

        /** Offers an unlinked result to the unlinked-result event's listeners. */
        private ProvisioningOffer $offer,
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
     * Run the completion and answer how it ended.
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
        $outcome = $this->steps($state, static fn (CompletionStep $step): bool => !$step->isLocked());

        if ($outcome->isReinitiating()) {
            return $this->reinitiation->run($flow, $outcome->state, $this->stage(CompletionStep::REPLAY_RECORDING));
        }

        if (!$outcome->state->hasRedirectTarget()) {

            $this->events->report($flow, $outcome);

            return self::rejected($outcome);
        }

        $discovery = $outcome->isProceeding() ? $this->locks->discover($outcome->state) : null;
        $finished  = DB::connection(StorageConnection::name())->transaction(fn (): CompletionResult|StageOutcome => $this->prepared($flow, $outcome, $discovery));

        return $finished instanceof CompletionResult ? $finished : $this->continued($flow, $finished);
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
     * Run the steps the filter names until one refuses or stops.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \Closure(\SineMacula\Laravel\Sso\Completion\Enums\CompletionStep): bool  $runs
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    private function steps(CompletionState $state, \Closure $runs): StageOutcome
    {
        $outcome = StageOutcome::proceed($state);

        foreach (CompletionStep::cases() as $step) {

            if (!$runs($step)) {
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
     * Refuse a re-initiation from any step but correlation, or a boundary from
     * any but provisioning.
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

        if ($outcome->isProvisioning() && $step !== CompletionStep::PROVISIONING) {
            throw new \LogicException(sprintf('Only the provisioning step stops at its boundary, not the [%s] step.', $step->value));
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
     * T2: lock, run the locked steps, and finish or stop at the provisioning
     * boundary.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Completion\StageOutcome  $outcome
     * @param  ?\SineMacula\Laravel\Sso\Linking\LinkingDiscovery  $discovery
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult|\SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \Throwable
     */
    private function prepared(Flow $flow, StageOutcome $outcome, ?LinkingDiscovery $discovery): CompletionResult|StageOutcome
    {
        $lock = $this->locks->take($outcome->state, $outcome->isProceeding(), true, $discovery);
        $ran  = $outcome->isProceeding() ? $this->locked($outcome->state, $lock, static fn (CompletionStep $step): bool => $step->isLocked()) : $outcome;

        if (!$ran->isProvisioning()) {
            return $this->finished($flow, $ran, $lock, false);
        }

        $this->stamp($lock, 'verified_at');

        $this->events->verified($ran->state);

        return $ran;
    }

    /**
     * Offer the result with no transaction open, then finish in T3.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Completion\StageOutcome  $boundary
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \Throwable
     */
    private function continued(Flow $flow, StageOutcome $boundary): CompletionResult
    {
        $this->offer->dispatch($boundary->state);

        return DB::connection(StorageConnection::name())->transaction(function () use ($flow, $boundary): CompletionResult {

            $lock = $this->locks->take($boundary->state, true, false);
            $ran  = $this->locked($boundary->state, $lock, static fn (CompletionStep $step): bool => $step->isInContinuation());

            return $this->finished($flow, $ran, $lock, true);
        });
    }

    /**
     * Refuse what no longer stands under the locks, or run the steps on the
     * locked rows.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionLock  $lock
     * @param  \Closure(\SineMacula\Laravel\Sso\Completion\Enums\CompletionStep): bool  $runs
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    private function locked(CompletionState $state, CompletionLock $lock, \Closure $runs): StageOutcome
    {
        $reason = $this->locks->refusal($lock, $state);

        if ($reason !== null) {
            return StageOutcome::refuse($state, $reason);
        }

        $held = $state->withConnection($lock->connection, $lock->domain, $lock->discovery)->withAuthorizationRequest($lock->request, $state->consumed, $state->application);

        return $this->steps($lock->enforcement === null ? $held : $held->withEnforcementPolicy($lock->enforcement->policy()), $runs);
    }

    /**
     * Discard a refused completion's reservation, mark the request completed,
     * report and answer.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Completion\StageOutcome  $outcome
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionLock  $lock
     * @param  bool  $verifiedReported
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function finished(Flow $flow, StageOutcome $outcome, CompletionLock $lock, bool $verifiedReported): CompletionResult
    {
        $candidate = $outcome->state->reservedCandidate;

        if ($outcome->isRefused() && $candidate !== null && $lock->connection !== null) {
            $this->storage->require('Discarding a reservation')->reservations()->discard($lock->connection, $candidate);
        }

        $this->stamp($lock, 'completed_at');

        $this->events->report($flow, $outcome, $verifiedReported);

        return $this->answer($outcome);
    }

    /**
     * Stamp the locked request's column with now.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionLock  $lock
     * @param  string  $column
     * @return void
     */
    private function stamp(CompletionLock $lock, string $column): void
    {
        $lock->request?->forceFill([$column => $this->clock->now()])->save();
    }

    /**
     * Answer a completion that consumed its request: `failed` or `completed`.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\StageOutcome  $outcome
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \LogicException
     */
    private function answer(StageOutcome $outcome): CompletionResult
    {
        $state       = $outcome->state;
        $application = $state->application          ?? throw new \LogicException(self::NO_APPLICATION);
        $request     = $state->authorizationRequest ?? throw new \LogicException(self::NO_REQUEST);
        $connection  = $state->connection           ?? throw new \LogicException(self::NO_CONNECTION);
        $redirectUri = $this->gate->redirectUri($application, $connection);
        $reference   = RequestReference::fromString($request->reference);

        if ($outcome->reason !== null) {
            return CompletionResult::failed($outcome->reason, $redirectUri, $application->delivery, $reference);
        }

        $handoff = $state->handoff ?? throw new \LogicException('A completion that ran every step holds its handoff.');

        return CompletionResult::completed($redirectUri, $application->delivery, $reference, $handoff);
    }
}
