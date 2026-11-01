<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\ApplicationRegistry;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

/**
 * Consumes the authorisation request a response answers (SSO-5.1, SSO-11.3,
 * SSO-11.5): the only place a request is consumed. The completion calls it once
 * the driver has read the response's correlation and before anything in the
 * response is validated, so a request is consumed once, whether the response
 * then passes or fails.
 *
 * In a transaction of its own on the storage connection (a savepoint inside the
 * caller's), the request is read with a locking read on the write connection,
 * so a lagging replica or the snapshot of a caller's older transaction never
 * answers: a SAML response's by its `InResponseTo` within the connection the
 * response arrived for, compared again exactly, never by its `RelayState`; any
 * other's by the digest of its state. None is `unknown`, and nothing is
 * consumed. A request consumed before, or one the single-use store has seen
 * (keyed by its id until its expiry, and at least a second), is `replayed`, and
 * is written nothing more. Otherwise it is consumed: it is recorded in the
 * store and its `consumed_at` set, both in the transaction, so racing servers
 * consume it exactly once.
 *
 * A request whose application is no longer registered is
 * `application_not_allowed`, with no redirect target, ahead of every other
 * reason. Its completion goes no further, so it is terminal at once: the same
 * write sets its `completed_at` with its `consumed_at`, since no later step
 * that would mark it completed runs without an application to answer to.
 *
 * Once that commits it is judged, in this order: a SAML request whose state's
 * digest is not the digest of the response's `RelayState`, compared in constant
 * time, or that the response gave no `RelayState` for, is `request_mismatch`
 * (SSO-5.3); a request a change to its connection voided is
 * `connection_unavailable`; one started through another connection than the
 * response arrived for is `connection_mismatch`; one whose expiry is not after
 * now is `request_expired`. Each of these keeps the application, so the
 * completion redirects to it with the failure. Otherwise it is `consumed`, with
 * what the driver is given of it: its PKCE verifier, still encrypted, with the
 * encrypter that decrypts it only when the driver asks for it to build the
 * token request; its nonce digest, the issuer it expects, its SAML request id
 * and when it started. Nothing is decrypted here, so a ciphertext no key
 * decrypts never stops a request being consumed.
 *
 * It reports nothing: the completion reports how it ended. A database error, a
 * store that cannot answer and a malformed application's settings propagate
 * (SSO-11.4); each is thrown inside the transaction, so the request stays
 * unconsumed.
 *
 * It holds the store, the encrypter, the registry and the clock, none of which
 * keeps anything of one request for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequestConsumption
{
    /** @var string The single-use namespace a consumed request is recorded in. */
    public const string NAMESPACE = 'authorization_request';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SingleUseStore  $store
     * @param  \SineMacula\Laravel\Sso\Contracts\SecretEncrypter  $encrypter
     * @param  \SineMacula\Laravel\Sso\Applications\ApplicationRegistry  $applications
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Records each consumed request once. */
        private SingleUseStore $store,

        /** Decrypts the PKCE verifier, once a driver asks for it. */
        private SecretEncrypter $encrypter,

        /** The registered applications. */
        private ApplicationRegistry $applications,

        /** The clock the consumption and the expiry are read from. */
        private Clock $clock,
    ) {}

    /**
     * Consume the request the correlation names, for a response that arrived
     * for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $routeConnection
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @return \SineMacula\Laravel\Sso\Flows\ConsumptionResult
     *
     * @throws \Throwable
     */
    public function consume(Connection $routeConnection, Correlation $correlation): ConsumptionResult
    {
        $now = $this->clock->now();

        $taken = DB::connection(StorageConnection::name())->transaction(fn (): array|ConsumptionResult => $this->take($routeConnection, $correlation, $now));

        return $taken instanceof ConsumptionResult ? $taken : $this->judge($taken[0], $taken[1], $routeConnection, $correlation, $now);
    }

    /**
     * In the transaction: find the request locked, and consume it unless it was
     * consumed before.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $routeConnection
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \SineMacula\Laravel\Sso\Models\AuthorizationRequest, 1: \SineMacula\Laravel\Sso\Applications\Application}|\SineMacula\Laravel\Sso\Flows\ConsumptionResult
     *
     * @throws \Throwable
     */
    private function take(Connection $routeConnection, Correlation $correlation, CarbonImmutable $now): array|ConsumptionResult
    {
        $request = self::lookup($routeConnection, $correlation);

        if ($request === null) {
            return ConsumptionResult::unknown();
        }

        if ($request->consumed_at !== null || !$this->isFirstRecord($request, $now)) {
            return ConsumptionResult::replayed($request);
        }

        return $this->consumed($request, $now);
    }

    /**
     * Consume the request and answer it with its registered application; one
     * whose application is no longer registered is completed in the same write
     * and refused `application_not_allowed`, with no redirect target.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \SineMacula\Laravel\Sso\Models\AuthorizationRequest, 1: \SineMacula\Laravel\Sso\Applications\Application}|\SineMacula\Laravel\Sso\Flows\ConsumptionResult
     *
     * @throws \InvalidArgumentException
     */
    private function consumed(AuthorizationRequest $request, CarbonImmutable $now): array|ConsumptionResult
    {
        $application = $this->applications->find($request->application);

        $request->forceFill(['consumed_at' => $now, 'completed_at' => $application === null ? $now : null])->save();

        return $application === null ? ConsumptionResult::refused(FailureReason::APPLICATION_NOT_ALLOWED, $request) : [$request, $application];
    }

    /**
     * Record the request in the single-use store until its expiry, and at least
     * a second from now; whether it was new.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \Throwable
     */
    private function isFirstRecord(AuthorizationRequest $request, CarbonImmutable $now): bool
    {
        $until = $now->addSecond()->max($request->expires_at);

        return $this->store->record(self::NAMESPACE, $request->id, $until) === SingleUseOutcome::RECORDED;
    }

    /**
     * Once consumed: the result the request, its application and the response
     * come to.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $routeConnection
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Sso\Flows\ConsumptionResult
     *
     * @throws \InvalidArgumentException
     */
    private function judge(AuthorizationRequest $request, Application $application, Connection $routeConnection, Correlation $correlation, CarbonImmutable $now): ConsumptionResult
    {
        $reason = self::refusal($request, $routeConnection, $correlation, $now);

        if ($reason !== null) {
            return ConsumptionResult::refused($reason, $request, $application);
        }

        return ConsumptionResult::consumed($request, $this->consumedRequest($request), $application);
    }

    /**
     * What the driver is given of the request: the PKCE verifier still
     * encrypted, with what decrypts it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\ConsumedRequest
     *
     * @throws \InvalidArgumentException
     */
    private function consumedRequest(AuthorizationRequest $request): ConsumedRequest
    {
        return new ConsumedRequest(
            purpose: $request->purpose,
            application: $request->application,
            reference: RequestReference::fromString($request->reference),
            startedAt: $request->created_at,
            expectedIssuer: $request->expected_issuer,
            issuerRequired: $request->issuer_required,
            samlRequestId: $request->saml_request_id,
            nonceDigest: $request->nonce_digest,
            codeVerifier: $request->code_verifier,
            encrypter: $this->encrypter,
        );
    }

    /**
     * Why the consumed request refuses the response, or `null` when it may go
     * on.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $routeConnection
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function refusal(AuthorizationRequest $request, Connection $routeConnection, Correlation $correlation, CarbonImmutable $now): ?FailureReason
    {
        return match (true) {
            self::isRelayStateMismatch($request, $correlation) => FailureReason::REQUEST_MISMATCH,
            $request->voided_at     !== null                   => FailureReason::CONNECTION_UNAVAILABLE,
            $request->connection_id !== $routeConnection->id   => FailureReason::CONNECTION_MISMATCH,
            $request->expires_at <= $now                       => FailureReason::REQUEST_EXPIRED,
            default                                            => null,
        };
    }

    /**
     * Whether a SAML response, found by its `InResponseTo`, carries no
     * `RelayState`, or one whose digest is not the request's state digest,
     * compared in constant time. A response found by its state never is.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @return bool
     */
    private static function isRelayStateMismatch(AuthorizationRequest $request, Correlation $correlation): bool
    {
        if ($correlation->samlRequestId === null) {
            return false;
        }

        $state = $correlation->state;

        return $state === null || !ConstantTime::matchesDigest($request->state_digest, $state->reveal());
    }

    /**
     * The request the correlation names, locked for update on the write
     * connection: by its SAML request id within the connection when the
     * response gave one, by its state's digest otherwise, and none when it gave
     * neither.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $routeConnection
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @return ?\SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private static function lookup(Connection $routeConnection, Correlation $correlation): ?AuthorizationRequest
    {
        if ($correlation->samlRequestId !== null) {
            return self::bySamlRequestId($routeConnection, $correlation->samlRequestId);
        }

        $digest = $correlation->stateDigest();

        return $digest === null ? null : self::locked()->where('state_digest', $digest)->first();
    }

    /**
     * The connection's request with exactly the SAML request id, locked for
     * update. A row the column's collation merely counts as equal is not found.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $routeConnection
     * @param  string  $samlRequestId
     * @return ?\SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private static function bySamlRequestId(Connection $routeConnection, string $samlRequestId): ?AuthorizationRequest
    {
        $request = self::locked()->where('connection_id', $routeConnection->id)->where('saml_request_id', $samlRequestId)->first();

        return $request?->saml_request_id === $samlRequestId ? $request : null;
    }

    /**
     * A locking read of the requests on the write connection (SSO-11.3).
     *
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Sso\Models\AuthorizationRequest>
     */
    private static function locked(): Builder
    {
        return AuthorizationRequest::query()->useWritePdo()->lockForUpdate();
    }
}
