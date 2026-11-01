<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Discovery;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\ApplicationGate;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestEvents;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Starts a flow by email domain (SSO-3.4, SSO-3.5): for an application that
 * offers discovery, the email's domain picks the usable connection it is
 * verified for and the flow starts through it; a domain that routes nowhere
 * leads to the application's fallback, in the same shape, status and time. Only
 * the domain is read, never a user, so the answer cannot tell whether a person
 * has an account.
 *
 * A discovery start runs outside any transaction open on the storage
 * connection: called inside one, it is a `LogicException` before anything else,
 * since a match calls the protocol driver, which may reach the identity
 * provider while the caller's transaction kept the connection's lock
 * (SSO-11.5).
 *
 * `start()` goes in a fixed order, and every refusal reports exactly one
 * `FlowFailed` (`Flow::AUTHORIZATION_REQUEST`) and writes no request:
 *
 * 1. the purpose's binding is checked by the check a named start runs
 *    (`AuthorizationRequestService::assertBinding()`): `sign_in` with no
 *    identity and no session, `link` for an identity with no session,
 *    `reauthenticate` for an identity on a session of 1 to 255 bytes; anything
 *    else is application code's mistake, an `InvalidArgumentException`, before
 *    anything else;
 * 2. the start is counted against the client's IP address and the email's
 *    normalised domain (SSO-11.8), the domain not at all when it does not
 *    normalise, and a full limit is `rate_limited` with its wait;
 * 3. the application is admitted (`Applications\ApplicationGate`), else
 *    `application_not_allowed`;
 * 4. the application must offer discovery while the `discovery` feature is on,
 *    else `feature_disabled`;
 * 5. the client's S256 challenge, when given, must be well formed, else
 *    `challenge_invalid`;
 * 6. `DomainRouter` resolves the email to a usable connection. A match starts
 *    through it (`AuthorizationRequestService::begin()`), which reports
 *    `AuthorizationRequestStarted`, or answers its own refusal (freshness,
 *    session, driver). A miss reports `discovery_no_match`, with the
 *    application and the purpose and never the email or its domain, and answers
 *    `AuthorizationRequestService::fallback()`: `started`, with a fresh
 *    reference that names no request, a fresh verifier when no challenge was
 *    given, and a redirect to the application's fallback.
 *
 * Every answer from step 2 on, a refusal included, is held by the `Pacer` until
 * the least time a discovery start takes has passed since it started; an
 * exception is not. Where the answer leads still shows whether a domain routes
 * to an identity provider, as any discovery does.
 *
 * The email and its domain appear in no event and no log; the public reference
 * is the only flow identifier either carries (SSO-9.8). A database error, a
 * misconfiguration and a driver's exception propagate (SSO-11.4).
 *
 * It holds the limiter, the gate, the router, the start helper, the reporter
 * and the pacer, none of which keeps anything of one request for the next, and
 * reads the request being served from the container on each call (SSO-11.2).
 * Resolve it from the container per request.
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
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Sso\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Sso\Applications\ApplicationGate  $gate
     * @param  \SineMacula\Laravel\Sso\Discovery\DomainRouter  $router
     * @param  \SineMacula\Laravel\Sso\Flows\AuthorizationRequestService  $requests
     * @param  \SineMacula\Laravel\Sso\Flows\RequestEvents  $events
     * @param  \SineMacula\Laravel\Sso\Discovery\Pacer  $pacer
     */
    public function __construct(

        /** The container the request being served is resolved from on each call. */
        private Container $container,

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
     * Start a flow for the application and the purpose through the connection
     * the email's domain routes to, or lead to the application's fallback, with
     * the client's S256 challenge, or with a verifier the package generates
     * when none is given; for the identity a `link` or a `reauthenticate` is
     * started for, on the session a `reauthenticate` is.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $email
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
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
        ?string $codeChallenge = null,
        ?IdentityReference $identity = null,
        ?string $sessionId = null,
    ): StartResult {
        StorageConnection::assertNoTransaction(self::INSIDE_TRANSACTION);
        AuthorizationRequestService::assertBinding($purpose, $identity, $sessionId);

        $startedAt = $this->pacer->start();
        $result    = $this->count($application, $purpose, $email, $codeChallenge, $identity, $sessionId);

        $this->pacer->finish($startedAt);

        return $result;
    }

    /**
     * Count the start against the client's IP address and the email's domain
     * (step 2), then admit the application.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $email
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Throwable
     */
    private function count(
        string $name,
        Purpose $purpose,
        #[\SensitiveParameter] string $email,
        ?string $codeChallenge,
        ?IdentityReference $identity,
        ?string $sessionId,
    ): StartResult {
        // A console caller has no client, and counts against no IP address.
        /** @var ?\Illuminate\Http\Request $request */
        $request = $this->container->bound('request') ? $this->container->make('request') : null;
        $attempt = $this->limiter->attempt(AttemptSubject::authorizationRequest($request?->ip(), DomainRouter::domainOf($email)));

        if ($attempt->retryAfter !== null) {

            $this->events->failed(FailureReason::RATE_LIMITED, $purpose, $identity, $sessionId);

            return StartResult::rateLimited($attempt->retryAfter);
        }

        return $this->admit($name, $purpose, $email, $codeChallenge, $identity, $sessionId);
    }

    /**
     * Admit the application, require that it offers discovery, and check the
     * challenge (steps 3 to 5), then route the email.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $email
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Throwable
     */
    private function admit(
        string $name,
        Purpose $purpose,
        #[\SensitiveParameter] string $email,
        ?string $codeChallenge,
        ?IdentityReference $identity,
        ?string $sessionId,
    ): StartResult {
        $application = $this->gate->admit($name)->application;

        if ($application === null) {
            return $this->refuse(FailureReason::APPLICATION_NOT_ALLOWED, $purpose, $identity, $sessionId);
        }

        $reason = self::refusalOf($application, $codeChallenge);

        if ($reason !== null) {
            return $this->refuse($reason, $purpose, $identity, $sessionId, $application);
        }

        return $this->route($application, $purpose, $email, $codeChallenge, $identity, $sessionId);
    }

    /**
     * Resolve the email to a connection and start through it, or report the
     * miss and lead to the application's fallback (step 6).
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $email
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Throwable
     */
    private function route(
        Application $application,
        Purpose $purpose,
        #[\SensitiveParameter] string $email,
        ?string $codeChallenge,
        ?IdentityReference $identity,
        ?string $sessionId,
    ): StartResult {
        $connection = $this->router->connectionFor($email);

        if ($connection === null) {

            $this->events->failed(FailureReason::DISCOVERY_NO_MATCH, $purpose, $identity, $sessionId, $application);

            return $this->requests->fallback($application, $codeChallenge !== null);
        }

        return $this->requests->begin($application, $purpose, $connection, $codeChallenge, $identity, $sessionId);
    }

    /**
     * Report a refused start, with the application once admitted, and answer
     * it.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @param  ?\SineMacula\Laravel\Sso\Applications\Application  $application
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \InvalidArgumentException
     */
    private function refuse(FailureReason $reason, Purpose $purpose, ?IdentityReference $identity, ?string $sessionId, ?Application $application = null): StartResult
    {
        $result = StartResult::refused($reason);

        $this->events->failed($reason, $purpose, $identity, $sessionId, $application);

        return $result;
    }

    /**
     * Why an admitted application may not start discovery with the challenge
     * (steps 4 and 5), or `null` when it may.
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
