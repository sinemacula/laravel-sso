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
 * Consumes the authorisation request a response answers, before the response is
 * validated.
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
     * Consume the request the correlation names.
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
     * Lock the request and consume it unless it was consumed before.
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
     * Consume the request; one whose application is gone is completed in the
     * same write, since no later step runs for it.
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
     * Record the request in the single-use store; whether it was new.
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
     * Judge the consumed request against the response.
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
     * What the driver is given of the request, its PKCE verifier still
     * encrypted.
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
     * Why the consumed request refuses the response, or `null` when it may.
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
            self::isRelayStateMismatch($request, $correlation)          => FailureReason::REQUEST_MISMATCH,
            $request->voided_at     !== null                            => FailureReason::CONNECTION_UNAVAILABLE,
            $request->connection_id !== $routeConnection->id            => FailureReason::CONNECTION_MISMATCH,
            $request->trust_version !== $routeConnection->trust_version => FailureReason::CONNECTION_UNAVAILABLE,
            $request->expires_at <= $now                                => FailureReason::REQUEST_EXPIRED,
            default                                                     => null,
        };
    }

    /**
     * Whether a SAML response found by its `InResponseTo` lacks the request's
     * `RelayState`.
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
     * Lock the request by SAML request id within the connection, else by state
     * digest.
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
     * Lock the connection's request with exactly the SAML request id; a row the
     * collation merely counts as equal is not found.
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
     * A locking read of the requests on the write connection.
     *
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Sso\Models\AuthorizationRequest>
     */
    private static function locked(): Builder
    {
        return AuthorizationRequest::query()->useWritePdo()->lockForUpdate();
    }
}
