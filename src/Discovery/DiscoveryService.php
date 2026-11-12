<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Discovery;

use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\ApplicationGate;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestEvents;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Starts a flow through the connection an email's domain routes to, or leads to
 * the application's fallback in the same shape, status and time.
 *
 * Call outside any transaction on the storage connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DiscoveryService
{
    /** @var string Why a start called inside a transaction on the storage connection is refused. */
    private const string INSIDE_TRANSACTION = 'A discovery start runs outside any transaction on the package\'s storage connection: it may call the protocol driver.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Sso\Applications\ApplicationGate  $gate
     * @param  \SineMacula\Laravel\Sso\Discovery\DomainRouter  $router
     * @param  \SineMacula\Laravel\Sso\Flows\AuthorizationRequestService  $requests
     * @param  \SineMacula\Laravel\Sso\Flows\RequestEvents  $events
     * @param  \SineMacula\Laravel\Sso\Discovery\Pacer  $pacer
     */
    public function __construct(

        /** Counts each start against the client's IP address and the email's domain. */
        private AttemptLimiter $limiter,

        /** Admits the application a start names. */
        private ApplicationGate $gate,

        /** Resolves the email's domain to the connection it routes to. */
        private DomainRouter $router,

        /** Starts through a matched connection, or answers the fallback. */
        private AuthorizationRequestService $requests,

        /** Reports each refusal and each miss. */
        private RequestEvents $events,

        /** Holds every answer until the least time a discovery start takes. */
        private Pacer $pacer,
    ) {}

    /**
     * Start a flow through the connection the email's domain routes to, or lead
     * to the application's fallback.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $email
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function start(
        string $application,
        Purpose $purpose,
        #[\SensitiveParameter] string $email,
        ClientContext $client,
        ?string $codeChallenge = null,
        ?Caller $caller = null,
    ): StartResult {
        StorageConnection::assertNoTransaction(self::INSIDE_TRANSACTION);
        AuthorizationRequestService::assertBinding($purpose, $caller);

        $startedAt = $this->pacer->start();
        $result    = $this->count($application, $purpose, $email, $codeChallenge, $caller, $client);

        $this->pacer->finish($startedAt);

        return $result;
    }

    /**
     * Count the start against the client's IP address and the email's domain.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $email
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Throwable
     */
    private function count(string $name, Purpose $purpose, #[\SensitiveParameter] string $email, ?string $codeChallenge, ?Caller $caller, ClientContext $client): StartResult
    {
        // A client with no IP address counts against none.
        $attempt = $this->limiter->attempt(AttemptSubject::authorizationRequest($client, DomainRouter::domainOf($email)));

        if ($attempt->retryAfter !== null) {

            $this->events->failed(FailureReason::RATE_LIMITED, $purpose, $caller, $client);

            return StartResult::rateLimited($attempt->retryAfter);
        }

        return $this->admit($name, $purpose, $email, $codeChallenge, $caller, $client);
    }

    /**
     * Admit the application and check it may start discovery with the
     * challenge.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $email
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Throwable
     */
    private function admit(string $name, Purpose $purpose, #[\SensitiveParameter] string $email, ?string $codeChallenge, ?Caller $caller, ClientContext $client): StartResult
    {
        $application = $this->gate->admit($name)->application;

        if ($application === null) {
            return $this->refuse(FailureReason::APPLICATION_NOT_ALLOWED, $purpose, $caller, $client);
        }

        $reason = self::refusalOf($application, $codeChallenge);

        if ($reason !== null) {
            return $this->refuse($reason, $purpose, $caller, $client, $application);
        }

        return $this->route($application, $purpose, $email, $codeChallenge, $caller, $client);
    }

    /**
     * Start through the connection the email routes to, or report the miss and
     * answer the fallback.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $email
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Throwable
     */
    private function route(
        Application $application,
        Purpose $purpose,
        #[\SensitiveParameter] string $email,
        ?string $codeChallenge,
        ?Caller $caller,
        ClientContext $client,
    ): StartResult {
        $connection = $this->router->connectionFor($email);

        if ($connection === null) {

            $this->events->failed(FailureReason::DISCOVERY_NO_MATCH, $purpose, $caller, $client, $application);

            return $this->requests->fallback($application, $codeChallenge !== null);
        }

        return $this->requests->begin($application, $purpose, $connection, $codeChallenge, $caller, $client);
    }

    /**
     * Report a refused start and answer it.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Applications\Application  $application
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \InvalidArgumentException
     */
    private function refuse(FailureReason $reason, Purpose $purpose, ?Caller $caller, ClientContext $client, ?Application $application = null): StartResult
    {
        $result = StartResult::refused($reason);

        $this->events->failed($reason, $purpose, $caller, $client, $application);

        return $result;
    }

    /**
     * Why the application may not start discovery with the challenge, or `null`
     * when it may.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  ?string  $codeChallenge
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     */
    private static function refusalOf(Application $application, ?string $codeChallenge): ?FailureReason
    {
        if (!AuthorizationRequestService::offersDiscovery($application)) {
            return FailureReason::FEATURE_DISABLED;
        }

        return AuthorizationRequestService::isChallenge($codeChallenge) ? null : FailureReason::CHALLENGE_INVALID;
    }
}
