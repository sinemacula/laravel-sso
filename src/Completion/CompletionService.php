<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Completes a flow at a connection's assertion consumer service or callback.
 *
 * Call outside any transaction on the storage connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CompletionService
{
    /** @var int The length of a connection's id, a ULID. */
    private const int CONNECTION_ID_LENGTH = 26;

    /** @var string Thrown for a completion inside a storage transaction. */
    private const string INSIDE_TRANSACTION = 'A completion runs outside any transaction on the package\'s storage connection: a rollback would undo its consumption.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionPipeline  $pipeline
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionEvents  $events
     */
    public function __construct(

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
     * Complete at the connection's endpoint with what arrived there.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint  $endpoint
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function complete(CompletionEndpoint $endpoint, string $connectionId, CompletionRequest $request, ClientContext $client): CompletionResult
    {
        StorageConnection::assertNoTransaction(self::INSIDE_TRANSACTION);

        $state   = CompletionState::arrived($connectionId, $request, $client);
        $attempt = $this->limiter->attempt(AttemptSubject::completion($client, $connectionId));

        if ($attempt->retryAfter !== null) {
            return $this->refuse($endpoint, $state, FailureReason::RATE_LIMITED, CompletionResult::rateLimited($attempt->retryAfter));
        }

        return $request->method === $endpoint->method() ? $this->admit($endpoint, $state) : $this->refuse($endpoint, $state, FailureReason::REQUEST_UNKNOWN);
    }

    /**
     * Find the connection, check its protocol completes here, then run the
     * steps.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint  $endpoint
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \Throwable
     */
    private function admit(CompletionEndpoint $endpoint, CompletionState $state): CompletionResult
    {
        $connection = $this->find($state->connectionId);

        if ($connection === null) {
            return $this->refuse($endpoint, $state, FailureReason::CONNECTION_UNAVAILABLE);
        }

        $state = $state->withConnection($connection);

        if (!$this->completesAt($endpoint, $connection->protocol)) {
            return $this->refuse($endpoint, $state, FailureReason::CONNECTION_UNAVAILABLE);
        }

        return $this->pipeline->run($endpoint->flow(), $state);
    }

    /**
     * Report a refusal before the steps and answer it, `rejected` by default.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint  $endpoint
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Sso\Completion\CompletionResult  $answer
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \InvalidArgumentException
     */
    private function refuse(CompletionEndpoint $endpoint, CompletionState $state, FailureReason $reason, ?CompletionResult $answer = null): CompletionResult
    {
        $this->events->report($endpoint->flow(), StageOutcome::refuse($state, $reason));

        return $answer ?? CompletionResult::rejected($reason);
    }

    /**
     * Whether the protocol completes at the endpoint; an application's own
     * protocol completes at either.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint  $endpoint
     * @param  string  $protocol
     * @return bool
     */
    private function completesAt(CompletionEndpoint $endpoint, string $protocol): bool
    {
        return match ($protocol) {
            Saml2Driver::NAME => $endpoint === CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            OidcDriver::NAME  => $endpoint === CompletionEndpoint::CALLBACK,
            default           => $this->protocols->isRegistered($protocol),
        };
    }

    /**
     * The connection with exactly the id, of any tenant; a row the collation
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
}
