<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\ApplicationGate;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Starts a flow (SSO-5.1, SSO-5.2, SSO-5.12): for an application and a purpose,
 * through a named connection, it records an authorisation request and answers
 * the request's public reference and the typed navigation that sends the
 * browser to the identity provider, with `Cache-Control: no-store` (SSO-9.8).
 *
 * A start runs outside any transaction open on the storage connection: called
 * inside one, it is a `LogicException` before anything else, since the driver
 * it calls may reach the identity provider while the caller's transaction kept
 * the connection's lock (SSO-11.5).
 *
 * `start()` goes in a fixed order, and every refusal reports exactly one
 * `FlowFailed` (`Flow::AUTHORIZATION_REQUEST`) and writes nothing:
 *
 * 1. the purpose's binding is checked: `sign_in` with no identity and no
 *    session, `link` for an identity with no session, `reauthenticate` for an
 *    identity on a session of 1 to 255 bytes; anything else is application
 *    code's mistake, an `InvalidArgumentException`, before anything else;
 * 2. the start is counted against the client's IP address (SSO-11.8), and a
 *    full limit is `rate_limited` with its wait;
 * 3. the application is admitted (`Applications\ApplicationGate`), else
 *    `application_not_allowed`;
 * 4. the client's S256 challenge of its own verifier is checked, else
 *    `challenge_invalid`; with none, the package generates the verifier, 256
 *    bits, and answers it once, in the body;
 * 5. the connection is read from the write connection (SSO-11.3), whatever its
 *    tenant; an unknown or unusable one is `connection_unavailable`, answered
 *    with the application's discovery fallback, in the same shape as a start,
 *    when the application offers discovery (SSO-3.5);
 * 6. a `link` asks the freshness contract (`sso.link.create`), else
 *    `freshness_required` (SSO-2.12);
 * 7. a `reauthenticate` asks `Contracts\ReauthenticationSessions::standing()`
 *    whether the identity is signed in through the connection on the session,
 *    else `session_ineligible` (SSO-5.10); that alone, since the exact link is
 *    judged at redemption, under the session's lock;
 * 8. the connection's trust version, as step 5 read it, is captured, the
 *    protocol state is generated (`ProtocolState`) and the driver asked to
 *    start, outside any transaction the start opens; a refused start is refused
 *    with the driver's reason;
 * 9. the request is stored through its model in a transaction on the storage
 *    connection: the digests of the state and the nonce, never either; the PKCE
 *    verifier encrypted; the challenge; the identity and the session; the trust
 *    version captured; and an expiry of `FlowSettings::requestTtlSeconds()`;
 *    the transaction first locks the connection's row, and a connection gone,
 *    changed in its switch, settings or secrets, or whose trust version is no
 *    longer the one captured (a certificate removed, say, which voided the
 *    requests stored before this one), is `connection_unavailable`, answered as
 *    step 5 answers it; a stored request raises the connection's flows version
 *    by one, under that lock, so a PostgreSQL `REPEATABLE READ` change that
 *    locks the row later fails to serialise rather than miss the request
 *    (`Connections\InFlightVoider`);
 * 10. `AuthorizationRequestStarted` is reported once that commits;
 * 11. the answer is `started`, with the generated verifier when one was.
 *
 * The public reference, the state, the nonce, the PKCE verifier and the
 * client's verifier are five independent random values (SSO-5.2, SSO-5.12); the
 * reference is the only flow identifier events and logs carry (SSO-9.8). A
 * database error, a misconfiguration and a driver's exception propagate
 * (SSO-11.4); a driver that answers a SAML request id already stored for the
 * connection is a driver's bug, and its unique violation propagates.
 *
 * It holds the limiter, the gate, the drivers, the freshness gate, the session
 * contract, the encrypter, the settings, the clock and the reporter, none of
 * which keeps anything of one request for the next, and reads the request being
 * served from the container on each call (SSO-11.2). Resolve it from the
 * container per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthorizationRequestService
{
    /** @var int The longest session id a request keeps, in bytes. */
    public const int MAX_SESSION_ID_LENGTH = 255;

    /** @var string Why a start called inside a transaction on the storage connection is refused. */
    private const string INSIDE_TRANSACTION = 'A start runs outside any transaction on the package\'s storage connection: it calls the protocol driver.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Sso\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Sso\Applications\ApplicationGate  $gate
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions  $sessions
     * @param  \SineMacula\Laravel\Sso\Contracts\SecretEncrypter  $encrypter
     * @param  \SineMacula\Laravel\Sso\Flows\FlowSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Flows\RequestEvents  $events
     */
    public function __construct(

        /** The container the request being served is resolved from on each call. */
        private Container $container,

        /** Counts each start against the client's IP address. */
        private AttemptLimiter $limiter,

        /** Admits the application a start names. */
        private ApplicationGate $gate,

        /** The protocol drivers, and whether a connection is usable. */
        private ProtocolManager $protocols,

        /** Asks the freshness contract before a `link` starts. */
        private FreshnessGate $freshness,

        /** Whether the identity of a `reauthenticate` is signed in on its session. */
        private ReauthenticationSessions $sessions,

        /** Encrypts the PKCE verifier for storage. */
        private SecretEncrypter $encrypter,

        /** The request's lifetime. */
        private FlowSettings $settings,

        /** The clock the expiry is read from. */
        private Clock $clock,

        /** Reports each start and each refusal. */
        private RequestEvents $events,
    ) {}

    /**
     * Start a flow for the application and the purpose through the connection,
     * with the client's S256 challenge, or with a verifier the package
     * generates when none is given; for the identity a `link` or a
     * `reauthenticate` is started for, on the session a `reauthenticate` is.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $connectionId
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
        string $connectionId,
        ?string $codeChallenge = null,
        ?IdentityReference $identity = null,
        ?string $sessionId = null,
    ): StartResult {
        StorageConnection::assertNoTransaction(self::INSIDE_TRANSACTION);
        self::assertBinding($purpose, $identity, $sessionId);

        // A console caller has no client, and counts against no IP address.
        /** @var ?\Illuminate\Http\Request $request */
        $request = $this->container->bound('request') ? $this->container->make('request') : null;
        $attempt = $this->limiter->attempt(AttemptSubject::authorizationRequest($request?->ip()));

        if ($attempt->retryAfter !== null) {

            $this->events->failed(FailureReason::RATE_LIMITED, $purpose, $identity, $sessionId);

            return StartResult::rateLimited($attempt->retryAfter);
        }

        return $this->admit($application, $purpose, $connectionId, $codeChallenge, $identity, $sessionId);
    }

    /**
     * Start a flow for an application already admitted, through a connection
     * already found and usable: the challenge, the purpose's checks, the
     * driver's start and the stored request (steps 4 and 6 to 11). Discovery
     * calls it once it has matched a connection; it counts no attempt, admits
     * nothing and finds nothing itself.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     *
     * @internal
     */
    public function begin(
        Application $application,
        Purpose $purpose,
        Connection $connection,
        ?string $codeChallenge,
        ?IdentityReference $identity,
        ?string $sessionId,
    ): StartResult {
        self::assertBinding($purpose, $identity, $sessionId);

        $reason = self::isChallenge($codeChallenge) ? $this->ineligibility($purpose, $connection, $identity, $sessionId) : FailureReason::CHALLENGE_INVALID;

        if ($reason !== null) {
            return $this->refuse($reason, $purpose, $identity, $sessionId, $application, $connection);
        }

        return $this->launch($application, $purpose, $connection, $codeChallenge, $identity, $sessionId);
    }

    /**
     * The answer that leads back to the application's discovery fallback, in
     * the same shape as a start (SSO-3.5): a fresh reference that names no
     * request, and a fresh verifier when the client sent no challenge. It
     * stores nothing and reports nothing; the caller reports why.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  bool  $challengeGiven
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     *
     * @internal
     */
    public function fallback(Application $application, bool $challengeGiven): StartResult
    {
        $navigation = self::toFallback($application);

        return StartResult::started(RequestReference::generate(), $navigation, $challengeGiven ? null : Verifier::generate());
    }

    /**
     * Whether the application offers discovery while the `discovery` feature is
     * on, so a start that names an unknown or unusable connection leads to its
     * fallback (SSO-3.5). Discovery asks it too before it routes an email.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function offersDiscovery(Application $application): bool
    {
        return $application->discoveryEnabled && Features::enabled(Feature::DISCOVERY);
    }

    /**
     * Whether the challenge is absent or has an S256 challenge's form.
     * Discovery asks it too before it routes an email.
     *
     * @param  ?string  $codeChallenge
     * @return bool
     *
     * @internal
     */
    public static function isChallenge(?string $codeChallenge): bool
    {
        return $codeChallenge === null || S256Challenge::isWellFormed($codeChallenge);
    }

    /**
     * Refuse an identity or a session that does not fit the purpose, and a
     * session id the request cannot keep: application code's mistake. Discovery
     * asks it too, before it counts the attempt.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return void
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function assertBinding(Purpose $purpose, ?IdentityReference $identity, ?string $sessionId): void
    {
        $required = match ($purpose) {
            Purpose::SIGN_IN        => [false, false, 'with no identity and no session'],
            Purpose::LINK           => [true, false, 'for an identity, with no session'],
            Purpose::REAUTHENTICATE => [true, true, 'for an identity, on a session'],
        };

        if ([$identity !== null, $sessionId !== null] !== [$required[0], $required[1]]) {
            throw new \InvalidArgumentException(sprintf('A `%s` flow is started %s.', $purpose->value, $required[2]));
        }

        // No session is no session id to judge, so it counts as one byte.
        $length = $sessionId === null ? 1 : strlen($sessionId);

        if ($length < 1 || $length > self::MAX_SESSION_ID_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A session id is 1 to %d bytes.', self::MAX_SESSION_ID_LENGTH));
        }
    }

    /**
     * The navigation to the application's discovery fallback.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @return \SineMacula\Laravel\Sso\Protocols\Navigation
     *
     * @throws \LogicException
     */
    private static function toFallback(Application $application): Navigation
    {
        $url = $application->discoveryFallbackUrl ?? throw new \LogicException(sprintf('The [%s] application has no discovery fallback.', $application->name));

        return Navigation::toApplication($url);
    }

    /**
     * Admit the application and check the challenge (steps 3 and 4), then find
     * the connection.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $connectionId
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Throwable
     */
    private function admit(string $name, Purpose $purpose, string $connectionId, ?string $codeChallenge, ?IdentityReference $identity, ?string $sessionId): StartResult
    {
        $application = $this->gate->admit($name)->application;

        if ($application === null) {
            return $this->refuse(FailureReason::APPLICATION_NOT_ALLOWED, $purpose, $identity, $sessionId);
        }

        if (!self::isChallenge($codeChallenge)) {
            return $this->refuse(FailureReason::CHALLENGE_INVALID, $purpose, $identity, $sessionId, $application);
        }

        return $this->locate($application, $purpose, $connectionId, $codeChallenge, $identity, $sessionId);
    }

    /**
     * Find the connection and judge whether it may be used (step 5), then
     * begin; an unknown or unusable one leads to the discovery fallback when
     * the application offers discovery, and is refused otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $connectionId
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Throwable
     */
    private function locate(Application $application, Purpose $purpose, string $connectionId, ?string $codeChallenge, ?IdentityReference $identity, ?string $sessionId): StartResult
    {
        $connection = $this->find($connectionId);

        if ($connection === null || !$this->protocols->isUsable($connection)) {
            return $this->unavailable($application, $purpose, $codeChallenge, $identity, $sessionId, $connection);
        }

        return $this->begin($application, $purpose, $connection, $codeChallenge, $identity, $sessionId);
    }

    /**
     * Report the connection unavailable, with what the start had established,
     * and answer the application's discovery fallback when it offers discovery,
     * or the refusal otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function unavailable(
        Application $application,
        Purpose $purpose,
        ?string $codeChallenge,
        ?IdentityReference $identity,
        ?string $sessionId,
        ?Connection $connection,
        ?RequestReference $reference = null,
    ): StartResult {
        $this->events->failed(FailureReason::CONNECTION_UNAVAILABLE, $purpose, $identity, $sessionId, $application, $connection, $reference);

        return self::offersDiscovery($application) ? $this->fallback($application, $codeChallenge !== null) : StartResult::refused(FailureReason::CONNECTION_UNAVAILABLE);
    }

    /**
     * Ask the driver to start and store the request (steps 8 to 11).
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Throwable
     */
    private function launch(
        Application $application,
        Purpose $purpose,
        Connection $connection,
        ?string $codeChallenge,
        ?IdentityReference $identity,
        ?string $sessionId,
    ): StartResult {
        [$verifier, $challenge] = self::challenge($codeChallenge);

        $trustVersion = $connection->trust_version;
        $reference    = RequestReference::generate();
        $state        = ProtocolState::generate();
        $request      = new StartRequest($purpose, $application->name, $reference, $state->state(), $state->nonce(), $state->codeVerifier());
        $start        = $this->protocols->protocol($connection->protocol)->start($connection, $request);

        if ($start->navigation === null) {
            return $this->refuse($start->reason ?? FailureReason::CONNECTION_UNAVAILABLE, $purpose, $identity, $sessionId, $application, $connection, $reference);
        }

        $stored = $this->store($connection, [
            'reference'         => $reference->value,
            'state_digest'      => $state->stateDigest(),
            'purpose'           => $purpose,
            'application'       => $application->name,
            'connection_id'     => $connection->id,
            'expected_issuer'   => $start->expectedIssuer,
            'issuer_required'   => $start->issuerRequired,
            'nonce_digest'      => $state->nonceDigest(),
            'code_verifier'     => $this->encrypter->encrypt($state->codeVerifier()->reveal()),
            'saml_request_id'   => $start->samlRequestId,
            'handoff_challenge' => $challenge,
            'trust_version'     => $trustVersion,
            'identity_type'     => $identity?->type,
            'identity_id'       => $identity?->id,
            'session_id'        => $sessionId,
            'expires_at'        => $this->clock->now()->addSeconds($this->settings->requestTtlSeconds()),
        ]);

        if (!$stored) {
            return $this->unavailable($application, $purpose, $codeChallenge, $identity, $sessionId, $connection, $reference);
        }

        return StartResult::started($reference, $start->navigation, $verifier);
    }

    /**
     * Store the request through its model, in a transaction on the storage
     * connection, and report it started once that commits; whether it was
     * stored.
     *
     * The driver started outside the transaction, from the connection as it was
     * read before, so the transaction first locks the connection's row, the
     * first lock of every flow, and stores nothing when the connection is gone,
     * its switch, settings or secrets changed since, or its trust version is no
     * longer the one the request captured: a change that voids its connection's
     * requests has then committed, and would not void this one.
     *
     * A stored request raises the connection's flows version by one, so the
     * insert also writes the locked row: a PostgreSQL `REPEATABLE READ` change
     * whose snapshot predates it then fails to serialise when it locks the row,
     * rather than go on to void the connection's requests without this one.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array<string, mixed>  $attributes
     * @return bool
     *
     * @throws \Throwable
     */
    private function store(Connection $connection, array $attributes): bool
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($connection, $attributes): bool {

            if (!self::isUnchanged($connection, $attributes['trust_version'])) {
                return false;
            }

            $request = new AuthorizationRequest;

            $request->forceFill($attributes)->save();

            // The insert also writes the locked connection's row.
            Connection::query()->useWritePdo()->whereKey($connection->id)->increment('flows_version');

            $this->events->started($connection, $request);

            return true;
        });
    }

    /**
     * Whether the connection, read again locked for update on the write
     * connection, still exists with the switch, settings and secrets it was
     * read with, and the trust version the request captured. The values are
     * compared as cast, the settings' maps whatever their key order, since a
     * JSON column need not keep the order it was given, and a connection just
     * created holds its values as given.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  mixed  $trustVersion
     * @return bool
     */
    private static function isUnchanged(Connection $connection, mixed $trustVersion): bool
    {
        $locked = Connection::query()->useWritePdo()->lockForUpdate()->whereKey($connection->id)->first();
        $trust  = static fn (Connection $row): array => [$row->enabled, self::sorted($row->settings), $row->secrets];

        return $locked !== null && $locked->trust_version === $trustVersion && $trust($locked) === $trust($connection);
    }

    /**
     * The value with the keys of every array in it sorted: a map's keys in
     * order, and a list left in its order.
     *
     * @param  array<array-key, mixed>  $value
     * @return array<array-key, mixed>
     */
    private static function sorted(array $value): array
    {
        ksort($value, SORT_STRING);

        return array_map(static fn (mixed $item): mixed => is_array($item) ? self::sorted($item) : $item, $value);
    }

    /**
     * Why the purpose may not start through the connection (steps 6 and 7), or
     * `null` when it may.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function ineligibility(Purpose $purpose, Connection $connection, ?IdentityReference $identity, ?string $sessionId): ?FailureReason
    {
        return match ($purpose) {
            Purpose::SIGN_IN        => null,
            Purpose::LINK           => $this->freshness->check(FreshnessOperation::LINK_CREATE)->isFresh() ? null : FailureReason::FRESHNESS_REQUIRED,
            Purpose::REAUTHENTICATE => $this->isSignedIn($connection, $identity, $sessionId) ? null : FailureReason::SESSION_INELIGIBLE,
        };
    }

    /**
     * Whether the identity is signed in through the connection on the session.
     * Only a `reauthenticate` asks, whose binding gives both.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return bool
     */
    private function isSignedIn(Connection $connection, ?IdentityReference $identity, ?string $sessionId): bool
    {
        assert($identity !== null && $sessionId !== null);

        return $this->sessions->standing($identity, $sessionId, $connection)->isSignedIn();
    }

    /**
     * Report a refused start, with what it had established, and answer it.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @param  ?\SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \InvalidArgumentException
     */
    private function refuse(
        FailureReason $reason,
        Purpose $purpose,
        ?IdentityReference $identity,
        ?string $sessionId,
        ?Application $application = null,
        ?Connection $connection = null,
        ?RequestReference $reference = null,
    ): StartResult {
        $result = StartResult::refused($reason);

        $this->events->failed($reason, $purpose, $identity, $sessionId, $application, $connection, $reference);

        return $result;
    }

    /**
     * The connection with exactly the id, of any tenant, read from the write
     * connection, or `null` when there is none. A row the column's collation
     * merely counts as equal is not found.
     *
     * @param  string  $connectionId
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     */
    private function find(string $connectionId): ?Connection
    {
        $connection = Connection::query()->useWritePdo()->whereKey($connectionId)->first();

        return $connection?->id === $connectionId ? $connection : null;
    }

    /**
     * The verifier the package generates when the client gave no challenge, and
     * the challenge the request keeps: the client's, or the generated
     * verifier's.
     *
     * @param  ?string  $codeChallenge
     * @return array{0: ?\SineMacula\Laravel\Sso\Flows\Verifier, 1: string}
     *
     * @throws \Random\RandomException
     */
    private static function challenge(?string $codeChallenge): array
    {
        if ($codeChallenge !== null) {
            return [null, $codeChallenge];
        }

        $verifier = Verifier::generate();

        return [$verifier, $verifier->challenge()->value];
    }
}
