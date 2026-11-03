<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Reauthenticating;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/reauthenticating.md` (SSO-5.10, SSO-9.5,
 * SSO-12.5), on the shared example harness, with the application's sessions in
 * its own table on the package's storage connection and its re-authentication
 * contract bound by its service provider: under the package's default every
 * start is refused; a sign-in records the exact link that established the
 * session; a reauthentication of that session is started with the client's
 * challenge, refused for a session the person is not signed in on, and
 * admitted in the application's transaction, renewing the session's
 * authentication time; a code started on another session renews only that
 * one, and the caller is told it is not reauthenticated; the standalone
 * redemption refuses the purpose and leaves the code unconsumed; and the
 * session's row is read with a locking read, so a session revoked, or bound to
 * another link, before the redemption is not renewed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(NoReauthenticationSessions::class)]
final class ReauthenticatingExampleTest extends ExampleTestCase
{
    /** @var string The session the person signs in on. */
    private const string SESSION = 'session-1';

    /** @var string The PKCE verifier the client keeps (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var string The challenge the client sends for it. */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's identity provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person who signs in. */
    private IdentityReference $person;

    /** @var string The link the person signs in through. */
    private string $linkId;

    /**
     * Create the application's session table, register its service provider,
     * make the tenant's OIDC connection, and link the person through it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::connection(StorageConnection::name())->create(Session::TABLE, static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('identity_type');
            $table->string('identity_id');
            $table->string('application');
            $table->string('connection_id');
            $table->string('sso_link_id')->nullable();
            $table->dateTime('authenticated_at')->nullable();
            $table->dateTime('revoked_at')->nullable();
        });

        app()->register(AppServiceProvider::class);

        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);
        $this->person       = new IdentityReference('user', 'person-1');
        $this->linkId       = (string) $this->linkThroughFlow($this->provider, $this->connectionId, $this->person)->linkId;
    }

    /**
     * Drop the application's session table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::connection(StorageConnection::name())->dropIfExists(Session::TABLE);

        parent::tearDown();
    }

    /**
     * Under the package's default no identity is signed in on any session, so a
     * reauthentication of the person's own session is refused
     * `session_ineligible`; with the application's sessions bound, it starts.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheBindingAnswersWhereTheDefaultRefuses(): void
    {
        $this->signIn(self::SESSION);

        app()->singleton(ReauthenticationSessions::class, NoReauthenticationSessions::class);

        $refused = $this->startReauthentication(self::SESSION);

        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::SESSION_INELIGIBLE, $refused->reason);

        app()->register(AppServiceProvider::class, true);

        self::assertInstanceOf(UserSessions::class, app(ReauthenticationSessions::class));
        self::assertTrue($this->startReauthentication(self::SESSION)->isStarted());
    }

    /**
     * An admitted sign-in writes the session in its own transaction, with the
     * identity, the application, the connection, the exact link that
     * established it, and when the provider authenticated the person.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASignInRecordsTheSessionsLink(): void
    {
        $signedIn = $this->signIn(self::SESSION);
        $session  = Session::on(StorageConnection::name())->findOrFail(self::SESSION);

        self::assertTrue($signedIn->isAdmitted());
        self::assertSame(['user', 'person-1', 'web', $this->connectionId], [$session->identity_type, $session->identity_id, $session->application, $session->connection_id]);
        self::assertSame($this->linkId, $session->sso_link_id);
        self::assertSame('2026-11-01T09:30:00Z', $session->authenticated_at?->toIso8601ZuluString());
    }

    /**
     * An hour after signing in, the person reauthenticates their own session:
     * the start is refused for a session they are not signed in on, and the
     * admitted code renews their session to when the provider authenticated
     * them again, telling the caller it is reauthenticated.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheSignedInSessionIsRenewed(): void
    {
        $this->signIn(self::SESSION);
        $this->clock->advance(3600);

        $elsewhere = $this->startReauthentication('session-2');

        self::assertTrue($elsewhere->isRefused());
        self::assertSame(FailureReason::SESSION_INELIGIBLE, $elsewhere->reason);
        self::assertNull($elsewhere->navigation);

        $start = $this->startReauthentication(self::SESSION);

        self::assertTrue($start->isStarted());

        $redeemed = $this->redeemReauthentication($this->respondAtProvider($this->provider, $this->connectionId, $start), self::SESSION);

        self::assertTrue($redeemed['result']->isAdmitted());
        self::assertSame(self::SESSION, $redeemed['result']->sessionId);
        self::assertTrue($redeemed['reauthenticated']);
        self::assertSame('2026-11-01T10:30:00Z', Session::on(StorageConnection::name())->findOrFail(self::SESSION)->authenticated_at?->toIso8601ZuluString());
    }

    /**
     * A code started on the person's session and redeemed by a caller on
     * another renews the session it was started on, never the caller's, and the
     * caller is not reauthenticated.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeOfAnotherSessionLeavesTheCallerUnauthenticated(): void
    {
        $this->signIn(self::SESSION);
        $this->clock->advance(3600);

        $start    = $this->startReauthentication(self::SESSION);
        $redeemed = $this->redeemReauthentication($this->respondAtProvider($this->provider, $this->connectionId, $start), 'session-2');

        self::assertTrue($redeemed['result']->isRedeemed());
        self::assertSame(self::SESSION, $redeemed['result']->sessionId);
        self::assertFalse($redeemed['reauthenticated']);
        self::assertSame('2026-11-01T10:30:00Z', Session::on(StorageConnection::name())->findOrFail(self::SESSION)->authenticated_at?->toIso8601ZuluString());
    }

    /**
     * Redeemed with no transaction open, a `reauthenticate` code is a
     * `LogicException`, and stays unconsumed: admitted afterwards, it renews.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testTheStandaloneRedemptionLeavesTheCodeUnconsumed(): void
    {
        $this->signIn(self::SESSION);
        $this->clock->advance(3600);

        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $this->startReauthentication(self::SESSION));
        $thrown   = null;

        try {
            app(HandoffRedemption::class)->redeem(Purpose::REAUTHENTICATE, 'web', $this->connectionId, $redirect->code(), self::VERIFIER);
        } catch (\LogicException $exception) {
            $thrown = $exception;
        }

        self::assertInstanceOf(\LogicException::class, $thrown);
        self::assertTrue($this->redeemReauthentication($redirect, self::SESSION)['reauthenticated']);
    }

    /**
     * The redemption reads the session's row with a locking read on the
     * package's storage connection, as the grammar compiles it, both for its
     * standing and for its renewal; on SQLite the lock compiles to a marker, so
     * a read without its lock fails here on every engine.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheRedemptionLocksTheSessionsRow(): void
    {
        $this->signIn(self::SESSION);

        $redirect   = $this->respondAtProvider($this->provider, $this->connectionId, $this->startReauthentication(self::SESSION));
        $connection = self::markLocksOnSqlite(DB::connection(StorageConnection::name()));
        $locking    = Session::on(StorageConnection::name())->lockForUpdate()->whereKey(self::SESSION)->limit(1)->toSql();

        $connection->enableQueryLog();

        self::assertTrue($this->redeemReauthentication($redirect, self::SESSION)['reauthenticated']);
        self::assertCount(2, array_keys(array_column($connection->getQueryLog(), 'query'), $locking, true));

        $connection->disableQueryLog();
    }

    /**
     * A session revoked between the start and the redemption is
     * `session_ineligible`, and is not renewed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARevokedSessionIsNotRenewed(): void
    {
        $this->signIn(self::SESSION);
        $this->clock->advance(3600);

        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $this->startReauthentication(self::SESSION));

        Session::on(StorageConnection::name())->whereKey(self::SESSION)->update(['revoked_at' => $this->clock->now()]);

        $this->assertRefusedAndNotRenewed($redirect);
    }

    /**
     * A session bound to another link than the one the code was issued through
     * is `session_ineligible`, and is not renewed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASessionOfAnotherLinkIsNotRenewed(): void
    {
        $this->signIn(self::SESSION);
        $this->clock->advance(3600);

        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $this->startReauthentication(self::SESSION));

        Session::on(StorageConnection::name())->whereKey(self::SESSION)->update(['sso_link_id' => 'another-link']);

        $this->assertRefusedAndNotRenewed($redirect);
    }

    /**
     * The code is refused `session_ineligible` at redemption, the caller is not
     * reauthenticated, and the session keeps its sign-in time.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\HandoffRedirect  $redirect
     * @return void
     */
    private function assertRefusedAndNotRenewed(HandoffRedirect $redirect): void
    {
        $redeemed = $this->redeemReauthentication($redirect, self::SESSION);

        self::assertTrue($redeemed['result']->isRefused());
        self::assertSame(FailureReason::SESSION_INELIGIBLE, $redeemed['result']->reason);
        self::assertFalse($redeemed['reauthenticated']);
        self::assertSame('2026-11-01T09:30:00Z', Session::on(StorageConnection::name())->findOrFail(self::SESSION)->authenticated_at?->toIso8601ZuluString());
    }

    /**
     * Start a reauthentication of the session for the person, with the client's
     * challenge, as the application's start endpoint does: the client keeps its
     * own verifier, so the start carries none.
     *
     * @param  string  $sessionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function startReauthentication(string $sessionId): StartResult
    {
        $connectionId  = $this->connectionId;
        $codeChallenge = self::CHALLENGE;
        $identity      = $this->person;

        // @snippet-start reauthenticating-start
        $start = app(AuthorizationRequestService::class)->start('web', Purpose::REAUTHENTICATE, $connectionId, $codeChallenge, $identity, $sessionId);
        // @snippet-end reauthenticating-start
        self::assertNull($start->verifier);

        return $start;
    }

    /**
     * Admit the `reauthenticate` code in the application's transaction, as its
     * redemption endpoint does for a caller on the session given, with the
     * verifier the client kept, and tell whether that caller's own session is
     * the one renewed.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\HandoffRedirect  $redirect
     * @param  string  $currentSessionId
     * @return array{result: \SineMacula\Laravel\Sso\Handoffs\RedemptionResult, reauthenticated: bool}
     */
    private function redeemReauthentication(HandoffRedirect $redirect, string $currentSessionId): array
    {
        $connectionId = $this->connectionId;
        $code         = $redirect->code();
        $verifier     = self::VERIFIER;

        // @snippet-start reauthenticating-admit
        $result = DB::connection(StorageConnection::name())->transaction(
            static fn (): RedemptionResult => app(HandoffRedemption::class)->admit(
                Purpose::REAUTHENTICATE,
                'web',
                $connectionId,
                $code,
                $verifier,
            ),
        );

        // The code renewed the session it was started on: only when that is
        // this caller's own is this caller reauthenticated
        $reauthenticated = $result->isRedeemed() && $result->sessionId === $currentSessionId;
        // @snippet-end reauthenticating-admit
        return ['result' => $result, 'reauthenticated' => $reauthenticated];
    }

    /**
     * Sign the person in through a whole `sign_in` flow at the provider,
     * writing the session the admitted code establishes in the same
     * transaction, as the application's sign-in endpoint does.
     *
     * @param  string  $sessionId
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Random\RandomException
     */
    private function signIn(string $sessionId): RedemptionResult
    {
        $connectionId = $this->connectionId;
        $start        = $this->startFlow(Purpose::SIGN_IN, $connectionId);
        $code         = $this->respondAtProvider($this->provider, $connectionId, $start)->code();
        $verifier     = self::verifierOf($start);

        // @snippet-start reauthenticating-sign-in
        $signedIn = DB::connection(StorageConnection::name())->transaction(static function () use ($sessionId, $connectionId, $code, $verifier): RedemptionResult {

            $result = app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $connectionId, $code, $verifier);

            if ($result->isAdmitted() && $result->linkedIdentity !== null) {
                Session::on(StorageConnection::name())->create([
                    'id'               => $sessionId,
                    'identity_type'    => $result->linkedIdentity->type,
                    'identity_id'      => $result->linkedIdentity->id,
                    'application'      => 'web',
                    'connection_id'    => $connectionId,
                    'sso_link_id'      => $result->linkId,
                    'authenticated_at' => $result->result?->authenticationContext->authenticatedAt,
                ]);
            }

            return $result;
        });
        // @snippet-end reauthenticating-sign-in
        self::assertTrue($signedIn->isAdmitted());

        return $signedIn;
    }

    /**
     * On SQLite, which compiles no lock, compile a lock for update to a marker
     * comment, so a read without its lock is told apart on every engine.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return \Illuminate\Database\Connection
     */
    private static function markLocksOnSqlite(Connection $connection): Connection
    {
        if ($connection->getDriverName() === 'sqlite') {
            $connection->setQueryGrammar(new class ($connection) extends SQLiteGrammar {
                /**
                 * Compile a lock for update to a marker comment.
                 *
                 * @param  \Illuminate\Database\Query\Builder  $query
                 * @param  bool|string  $value
                 * @return string
                 */
                #[\Override]
                protected function compileLock(Builder $query, $value): string
                {
                    return $value === true ? ' /* for update */' : '';
                }
            });
        }

        return $connection;
    }
}
