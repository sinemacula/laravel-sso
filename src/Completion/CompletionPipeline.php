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
 * Runs a completion's steps in `Enums\CompletionStep`'s fixed order (SSO-5.6,
 * SSO-8.6), each through the stage registered for it (`stageClass()`), through
 * the frozen state machine of `docs/design/linking.md`, and answers how the
 * completion ended (SSO-5.7).
 *
 * 1. Correlation, consumption (T1, a transaction of its own that commits before
 *    validation) and validation run outside any transaction the pipeline opens,
 *    so the request is consumed whether the response then passes or fails, and
 *    the validation may fetch.
 * 2. T2, one transaction on the storage connection, takes the package's lock
 *    order (`Completion\CompletionLocks`), having found by plain reads, before
 *    it opens, whose identity guard comes first, and, for a completion still
 *    going on, refuses what no longer stands, then runs every locked step, in
 *    order, on the rows as locked, with the policy the locked rule gives. On
 *    PostgreSQL under `REPEATABLE READ`, a completion that waited on a change
 *    may fail to serialise instead: the error propagates as a server error.
 * 3. A linked result, an eligible `link` or `reauthenticate` and a successful
 *    reservation finish in T2: the handoff is issued, the request's
 *    `completed_at` is set, whether it completed or was refused, a reservation
 *    made by a completion that then refused is discarded, and the completion is
 *    reported (`Completion\CompletionEvents`), so its events reach listeners
 *    once that commits and never on a rollback (SSO-10.5).
 * 4. A genuinely unlinked `sign_in` holding no reservation stops at the
 *    provisioning boundary: T2 commits its replay record and its `verified_at`,
 *    leaves `completed_at` unset, issues no handoff and reports
 *    `ResultVerified` once; what lets it go on stays only in memory, so a crash
 *    leaves a request consumed and unfinished that nothing resumes.
 * 5. The unlinked-result event is dispatched with no package transaction open
 *    and the grant closed in `finally` (`Completion\ProvisioningOffer`). A
 *    listener's exception ends the completion as a server error, and nothing
 *    dispatches again.
 * 6. T3 takes the lock order again, without a domain, refuses what no longer
 *    stands and runs only the steps of the final continuation
 *    (`CompletionStep::isInContinuation()`): the link is resolved anew, and
 *    neither replay nor provisioning is repeated. It sets `completed_at` and
 *    reports only how the completion ended.
 *
 * An unsolicited SAML response is handed to re-initiation by the correlation
 * step (`StageOutcome::reinitiate()`, SSO-5.8): no further step runs, no
 * request is consumed, and `Completion\UnsolicitedReinitiation` answers it,
 * recording its assertion through the stage registered for `replay_recording`
 * under the connection's lock alone. Any other step handing a completion to
 * re-initiation, or any but the provisioning step stopping at its boundary, is
 * a misconfiguration, a `LogicException`.
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
 * answered as `failed` or `rejected` (SSO-11.4); thrown inside a transaction,
 * it rolls that transaction back, so no code is kept, nothing it held is
 * reported and `completed_at` stays unset.
 *
 * Each stage is resolved from the container per completion, so an application
 * or a test may bind its own for a step. It holds the container, the
 * application gate, the clock, the reporter, the re-initiation, the locks, the
 * storage binding and the offer, none of which keeps anything of one completion
 * for the next (SSO-11.2).
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
        'purpose_rules'      => CheckPurpose::class,
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
     * Run the steps the filter names, in order, until one refuses or stops the
     * completion.
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
     * What the step's stage answered, once it is known that only the
     * correlation step hands a completion to re-initiation, and only the
     * provisioning step stops at its boundary.
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
     * T2: lock in order, run the locked steps of a completion still going on,
     * and finish it, or stop it at the provisioning boundary with what it
     * recorded.
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
     * The final continuation: offer the result with no transaction open, then,
     * in T3, lock in order again, run its steps and finish.
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
     * Refuse what no longer stands under the locks, and run the steps the
     * filter names otherwise, on the rows as locked, with the policy the locked
     * rule gives.
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
     * Discard the reservation of a completion that refused, mark the request
     * completed, report how it ended and answer it.
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
     * Stamp the locked request's column with now, when its row is still there.
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
