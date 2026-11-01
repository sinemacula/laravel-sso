<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Completes a flow where the identity provider sends the browser back (SSO-5.5,
 * SSO-5.6, SSO-5.7, SSO-12.1): one call for a connection's SAML assertion
 * consumer service, one for its OIDC callback, each answering a
 * `Completion\CompletionResult` the application's controller turns into its
 * response (`Responses\CompletionResponses`).
 *
 * The connection is the one the application's route names, whose endpoint URL
 * the endpoint resolver built from configuration, never from the request
 * (SSO-5.5).
 *
 * A completion runs outside any transaction open on the storage connection:
 * called inside one, it is a `LogicException` before anything is written, the
 * attempt included. A caller's rollback would otherwise undo the request's
 * consumption, so the same response could be replayed (SSO-5.1), and the
 * caller's transaction would keep the connection's lock across the driver's
 * validation, which may reach the identity provider (SSO-11.5).
 *
 * Before the completion's steps run, in this order, each refusal reporting
 * exactly one `FlowFailed` (`Flow::ASSERTION` or `Flow::CALLBACK`):
 *
 * 1. the completion is counted against the client's IP address and the
 *    connection (SSO-11.8), and a full limit is `rate_limited` with its wait;
 * 2. the method must be the endpoint's: `POST` (HTTP-POST binding) at the
 *    assertion consumer service, `GET` at the callback, compared exactly;
 *    anything else is `rejected(request_unknown)`;
 * 3. the connection is read by exactly its id, of any tenant, from the write
 *    connection (SSO-11.3); an unknown one is
 *    `rejected(connection_unavailable)`;
 * 4. its protocol must complete at the endpoint: `saml2` at the assertion
 *    consumer service, `oidc` at the callback, and a protocol an application
 *    registered, which the package cannot place, at either, while its driver is
 *    registered; anything else is `rejected(connection_unavailable)`.
 *
 * A connection that is no longer usable (disabled since the start, say) is
 * refused only once the request the response names is consumed, so its request
 * is consumed, and its failure redirected to the application (SSO-5.7). Then
 * `Completion\CompletionPipeline` runs the steps and answers.
 *
 * A database error, a misconfiguration and a contract's exception propagate as
 * server errors (SSO-11.4), never as a failure.
 *
 * It holds the container, the limiter, the drivers' registry, the pipeline and
 * the reporter, none of which keeps anything of one request for the next, and
 * reads the request being served from the container on each call (SSO-11.2).
 * Resolve it from the container per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CompletionService
{
    /** @var int The length of a connection's id, a ULID: a longer one names no connection. */
    private const int CONNECTION_ID_LENGTH = 26;

    /** @var string Why a completion called inside a transaction on the storage connection is refused. */
    private const string INSIDE_TRANSACTION = 'A completion runs outside any transaction on the package\'s storage connection: a rollback would undo its consumption.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Sso\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionPipeline  $pipeline
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionEvents  $events
     */
    public function __construct(

        /** The container the request being served is resolved from on each call. */
        private Container $container,

        /** Counts each completion against the IP address and the connection. */
        private AttemptLimiter $limiter,

        /** Whether a protocol is registered. */
        private ProtocolManager $protocols,

        /** Runs the completion's steps. */
        private CompletionPipeline $pipeline,

        /** Reports each refusal before the steps. */
        private CompletionEvents $events,
    ) {}

    /**
     * Complete at the connection's SAML assertion consumer service, with what
     * the identity provider's response posted.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \Throwable
     */
    public function assertionConsumerService(string $connectionId, CompletionRequest $request): CompletionResult
    {
        return $this->complete(Flow::ASSERTION, 'POST', $connectionId, $request);
    }

    /**
     * Complete at the connection's OIDC callback, with the authorisation
     * response's query.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \Throwable
     */
    public function callback(string $connectionId, CompletionRequest $request): CompletionResult
    {
        return $this->complete(Flow::CALLBACK, 'GET', $connectionId, $request);
    }

    /**
     * Count the completion, and refuse a method the endpoint does not take
     * (steps 1 and 2), then find the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  string  $method
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    private function complete(Flow $flow, string $method, string $connectionId, CompletionRequest $request): CompletionResult
    {
        StorageConnection::assertNoTransaction(self::INSIDE_TRANSACTION);

        $state   = CompletionState::arrived($connectionId, $request);
        $attempt = $this->limiter->attempt(AttemptSubject::completion($this->ip(), $connectionId));

        if ($attempt->retryAfter !== null) {
            return $this->refuse($flow, $state, FailureReason::RATE_LIMITED, CompletionResult::rateLimited($attempt->retryAfter));
        }

        return $request->method === $method ? $this->admit($flow, $state) : $this->refuse($flow, $state, FailureReason::REQUEST_UNKNOWN);
    }

    /**
     * Find the connection and check its protocol completes at the endpoint
     * (steps 3 and 4), then run the completion's steps.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \Throwable
     */
    private function admit(Flow $flow, CompletionState $state): CompletionResult
    {
        $connection = $this->find($state->connectionId);

        if ($connection === null) {
            return $this->refuse($flow, $state, FailureReason::CONNECTION_UNAVAILABLE);
        }

        $state = $state->withConnection($connection);

        if (!$this->completesAt($flow, $connection->protocol)) {
            return $this->refuse($flow, $state, FailureReason::CONNECTION_UNAVAILABLE);
        }

        return $this->pipeline->run($flow, $state);
    }

    /**
     * Report a completion refused before its steps, and answer it: `rejected`
     * for the reason unless the answer is given.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Sso\Completion\CompletionResult  $answer
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \InvalidArgumentException
     */
    private function refuse(Flow $flow, CompletionState $state, FailureReason $reason, ?CompletionResult $answer = null): CompletionResult
    {
        $this->events->report($flow, StageOutcome::refuse($state, $reason));

        return $answer ?? CompletionResult::rejected($reason);
    }

    /**
     * Whether a connection over the protocol completes at the flow's endpoint:
     * `saml2` at the assertion consumer service, `oidc` at the callback, and a
     * protocol an application registered at either.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  string  $protocol
     * @return bool
     */
    private function completesAt(Flow $flow, string $protocol): bool
    {
        return match ($protocol) {
            Saml2Driver::NAME => $flow === Flow::ASSERTION,
            OidcDriver::NAME  => $flow === Flow::CALLBACK,
            default           => $this->protocols->isRegistered($protocol),
        };
    }

    /**
     * The connection with exactly the id, of any tenant, read from the write
     * connection, or `null` when there is none. An id longer than a ULID, or
     * empty, names none and is not looked up; a row the column's collation
     * merely counts as equal is not found.
     *
     * @param  string  $connectionId
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     */
    private function find(string $connectionId): ?Connection
    {
        if ($connectionId === '' || strlen($connectionId) > self::CONNECTION_ID_LENGTH) {
            return null;
        }

        $connection = Connection::query()->useWritePdo()->whereKey($connectionId)->first();

        return $connection?->id === $connectionId ? $connection : null;
    }

    /**
     * The IP address of the request being served, or `null` when none is bound,
     * as in a console command, which counts against no IP address.
     *
     * @return ?string
     */
    private function ip(): ?string
    {
        /** @var ?\Illuminate\Http\Request $request */
        $request = $this->container->bound('request') ? $this->container->make('request') : null;

        return $request?->ip();
    }
}
