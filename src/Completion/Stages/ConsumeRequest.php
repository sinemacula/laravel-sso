<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\ConsumptionResult;
use SineMacula\Laravel\Sso\Flows\Enums\ConsumptionStatus;
use SineMacula\Laravel\Sso\Flows\RequestConsumption;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;

/**
 * The `consumption` step (SSO-5.1, SSO-5.6, SSO-11.5): the request the
 * correlation names is consumed through `Flows\RequestConsumption`, the only
 * place a request is consumed, before anything in the response is validated, so
 * it is consumed once whether the response then passes or fails.
 *
 * The consumption runs in a transaction of its own on the storage connection
 * (the completion runs outside any other, `CompletionService`) that first locks
 * the row of the connection the response arrived for, so a completion takes its
 * locks in the package's order, the connection's row before its request's, and
 * commits the consumption before the response is validated. A change that voids
 * the connection's requests (a disable, a trust change) takes the same locks in
 * the same order, and the two never deadlock.
 *
 * The result maps to the state:
 *
 * - `consumed`: the request, what the driver is given of it and its application
 *   go on;
 * - `refused` with the application still registered: refused for the reason,
 *   with the request and the application, so the completion redirects to it
 *   with the failure (SSO-5.7). The driver is never given a refused request, so
 *   it is kept without its nonce digest or its PKCE verifier;
 * - `refused` without the application (`application_not_allowed`): refused,
 *   with no trusted redirect target;
 * - `unknown` and `replayed`: refused with `request_unknown`, with no trusted
 *   redirect target.
 *
 * It holds the consumption, which keeps nothing of one completion for the next
 * (SSO-11.2). A database error propagates (SSO-11.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConsumeRequest implements CompletionStage
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\RequestConsumption  $consumption
     */
    public function __construct(

        /** Consumes the request a response answers. */
        private RequestConsumption $consumption,
    ) {}

    /**
     * Consume the request the correlation names, with the connection's row
     * locked first.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    #[\Override]
    public function run(CompletionState $state): StageOutcome
    {
        $result = $this->consume(self::connection($state), self::correlation($state));

        return match ($result->status) {
            ConsumptionStatus::CONSUMED                             => self::consumed($state, $result),
            ConsumptionStatus::REFUSED                              => self::refused($state, $result),
            ConsumptionStatus::UNKNOWN, ConsumptionStatus::REPLAYED => StageOutcome::refuse($state, FailureReason::REQUEST_UNKNOWN),
        };
    }

    /**
     * Consume the request the correlation names, in a transaction on the
     * storage connection that locks the connection's row first.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @return \SineMacula\Laravel\Sso\Flows\ConsumptionResult
     *
     * @throws \Throwable
     */
    private function consume(Connection $connection, Correlation $correlation): ConsumptionResult
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($connection, $correlation): ConsumptionResult {

            Connection::query()->useWritePdo()->lockForUpdate()->whereKey($connection->id)->first();

            return $this->consumption->consume($connection, $correlation);
        });
    }

    /**
     * The connection the request is consumed through.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \LogicException
     */
    private static function connection(CompletionState $state): Connection
    {
        return $state->connection ?? throw new \LogicException('A request is consumed once its connection is read.');
    }

    /**
     * The correlation that names the request.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     *
     * @throws \LogicException
     */
    private static function correlation(CompletionState $state): Correlation
    {
        return $state->correlation ?? throw new \LogicException('A request is consumed once the response is correlated.');
    }

    /**
     * Go on with the consumed request, what the driver is given of it and its
     * application.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Flows\ConsumptionResult  $result
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    private static function consumed(CompletionState $state, ConsumptionResult $result): StageOutcome
    {
        $request     = $result->request     ?? throw new \LogicException('A consumed result holds its request.');
        $consumed    = $result->consumed    ?? throw new \LogicException('A consumed result holds what the driver is given.');
        $application = $result->application ?? throw new \LogicException('A consumed result holds its application.');

        return StageOutcome::proceed($state->withAuthorizationRequest($request, $consumed, $application));
    }

    /**
     * Refuse for the consumption's reason, with the request and its application
     * when the application is still registered.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Flows\ConsumptionResult  $result
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    private static function refused(CompletionState $state, ConsumptionResult $result): StageOutcome
    {
        $reason      = $result->reason  ?? throw new \LogicException('A refused result holds its reason.');
        $request     = $result->request ?? throw new \LogicException('A refused result holds its request.');
        $application = $result->application;

        if ($application === null) {
            return StageOutcome::refuse($state, $reason);
        }

        return StageOutcome::refuse($state->withAuthorizationRequest($request, self::withoutSecrets($request), $application), $reason);
    }

    /**
     * What a refused request is kept as: its purpose, application, reference,
     * start and expectations, never its nonce digest or its PKCE verifier,
     * since no driver is given it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\ConsumedRequest
     *
     * @throws \InvalidArgumentException
     */
    private static function withoutSecrets(AuthorizationRequest $request): ConsumedRequest
    {
        return new ConsumedRequest(
            purpose: $request->purpose,
            application: $request->application,
            reference: RequestReference::fromString($request->reference),
            startedAt: $request->created_at,
            expectedIssuer: $request->expected_issuer,
            issuerRequired: $request->issuer_required,
            samlRequestId: $request->saml_request_id,
        );
    }
}
