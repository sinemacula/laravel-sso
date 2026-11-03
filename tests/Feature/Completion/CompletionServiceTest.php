<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Links\DelegatingLinkStorage;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\Fixtures\Secrets\CountingSecretEncrypter;
use Tests\TestCase;

/**
 * Feature tests for completing a flow at a connection's assertion consumer
 * service and callback (SSO-5.5, SSO-5.6, SSO-5.7, SSO-6.10, SSO-8.6, SSO-9.2,
 * SSO-4.6, SSO-11.8, SSO-12.1): every outcome and its exact `CompletionResult`,
 * the method and the protocol each endpoint takes, an unknown connection, a
 * connection disabled after the start, a request of another connection, the
 * expiry at its second and either side, a replay, an unlinked sign-in with
 * unlinked handoffs off and on, enforcement satisfied, unsatisfied and its
 * version, the policy turned off before issuance, the provider's deadline
 * limiting the session and ignored, every field of the grant, a full limit, and
 * a database error that propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionPipeline::class)]
final class CompletionServiceTest extends TestCase
{
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-completed-request-01';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Cq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var string The client's S256 challenge the request keeps. */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var string The `web` application's redirect URI. */
    private const string REDIRECT_URI = 'https://app.example.com/sso';

    /** @var string The `native` application's redirect URI. */
    private const string NATIVE_REDIRECT_URI = 'com.example.app:/sso';

    /** @var string A connection id no connection has. */
    private const string UNKNOWN_ID = '01jbz0000000000000000000zz';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Protocols\VerifyingDriver The driver the connection runs over. */
    private VerifyingDriver $driver;

    /** @var \Tests\Fixtures\Handoffs\RecordingHandoffIssuer The handoff issuer. */
    private RecordingHandoffIssuer $issuer;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /** @var ?\SineMacula\Laravel\Sso\Identities\IdentityReference The identity every result is linked to. */
    private ?IdentityReference $linked = null;

    /** @var list<array{0: string, 1: string}> Each tenant and application the enforcement was asked about. */
    private array $enforcementAsked = [];

    /** @var int How many times the deadline contract was asked. */
    private int $deadlineAsked = 0;

    /**
     * Bind a fixed clock, the recording issuer, a linker and a request from an
     * IP address, register the applications and the driver, create the tables
     * and a usable connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock  = new FixedClock('2026-11-01T09:30:00Z');
        $this->driver = new VerifyingDriver;
        $this->issuer = new RecordingHandoffIssuer;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(HandoffIssuer::class, $this->issuer);
        $this->app?->instance(Linker::class, self::linker(fn (VerifiedResult $result): ?IdentityReference => $this->linked));

        $this->linked = new IdentityReference('App\Models\User', '42');
        $this->app?->instance('request', Request::create('/auth/sso/connections/x/callback', 'GET', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', [
            'web'    => ['redirect_uri' => self::REDIRECT_URI, 'external_sign_in' => true],
            'native' => [
                'redirect_uri'        => self::NATIVE_REDIRECT_URI,
                'external_sign_in'    => true,
                'delivery'            => 'query',
                'unlinked_handoffs'   => true,
                'handoff_ttl_seconds' => 120,
            ],
        ]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::migration(self::SINGLE_USE_MIGRATION)->up(); // @phpstan-ignore method.notFound
        self::migration(self::RATE_LIMITS_MIGRATION)->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeVerifyingConnection();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::migration(self::RATE_LIMITS_MIGRATION)->down(); // @phpstan-ignore method.notFound
        self::migration(self::SINGLE_USE_MIGRATION)->down(); // @phpstan-ignore method.notFound
        $this->dropDomainsTable();
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A callback whose response the driver verifies completes: a code issued
     * for the `web` application's redirect URI, in the fragment, with the
     * request's reference; the request consumed and completed now, and the
     * driver given the request it was started as, its PKCE verifier decrypted
     * only once the driver asks for it, which this driver never does.
     *
     * @return void
     */
    public function testACallbackCompletesWithTheHandoffAtTheRedirectUri(): void
    {
        $request   = $this->request();
        $encrypter = new CountingSecretEncrypter(app(SecretEncrypter::class));

        $this->app?->instance(SecretEncrypter::class, $encrypter);

        $this->clock->advance(5);

        $result = $this->completeAtCallback();

        self::assertTrue($result->isCompleted());
        self::assertResult($this->completedResult(expiresAt: '2026-11-01T09:31:05+00:00'), $result);
        self::assertCount(1, $this->issuer->grants());

        $row = $this->reread($request);

        self::assertSame('2026-11-01T09:30:05+00:00', $row->consumed_at?->toIso8601String());
        self::assertSame('2026-11-01T09:30:05+00:00', $row->completed_at?->toIso8601String());
        self::assertNull($row->voided_at);

        $consumed = $this->driver->completions();

        self::assertCount(1, $consumed);
        self::assertSame(self::REFERENCE, $consumed[0]->reference->value);
        self::assertSame('web', $consumed[0]->application);
        self::assertSame(Purpose::SIGN_IN, $consumed[0]->purpose);
        self::assertSame(0, $encrypter->decryptions);
        self::assertSame('the-pkce-verifier-of-the-completed-request-0', $consumed[0]->codeVerifier()?->reveal());
        self::assertSame(1, $encrypter->decryptions);
    }

    /**
     * An assertion posted to the assertion consumer service completes the same
     * way.
     *
     * @return void
     */
    public function testAnAssertionPostedToTheAssertionConsumerServiceCompletes(): void
    {
        $this->request();

        $result = $this->completeAtAssertionConsumerService();

        self::assertResult($this->completedResult(), $result);
        self::assertCount(1, $this->issuer->grants());
    }

    /**
     * The callback takes `GET` only, compared exactly: any other method is
     * rejected with `request_unknown`, before the connection is read or the
     * response correlated, and consumes nothing.
     *
     * @return void
     */
    public function testTheCallbackTakesOnlyGet(): void
    {
        $request = $this->request();

        foreach (['POST', 'HEAD', 'get', 'PUT'] as $method) {
            self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtCallback(method: $method));
        }

        self::assertSame(0, $this->driver->correlations());
        self::assertNull($this->reread($request)->consumed_at);
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * The assertion consumer service takes `POST` only.
     *
     * @return void
     */
    public function testTheAssertionConsumerServiceTakesOnlyPost(): void
    {
        $request = $this->request();

        foreach (['GET', 'post', 'PUT'] as $method) {
            self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtAssertionConsumerService(method: $method));
        }

        self::assertSame(0, $this->driver->correlations());
        self::assertNull($this->reread($request)->consumed_at);
    }

    /**
     * A connection no row has, an empty id, an id longer than a ULID and one
     * that differs only in case are rejected with `connection_unavailable`.
     *
     * @return void
     */
    public function testAnUnknownConnectionIsRejected(): void
    {
        $request = $this->request();

        foreach ([self::UNKNOWN_ID, '', $this->connection->id . 'z', strtoupper($this->connection->id)] as $id) {
            self::assertResult(self::rejectedResult(FailureReason::CONNECTION_UNAVAILABLE), $this->completeAtCallback(connectionId: $id));
            self::assertResult(self::rejectedResult(FailureReason::CONNECTION_UNAVAILABLE), $this->completeAtAssertionConsumerService(connectionId: $id));
        }

        self::assertSame(0, $this->driver->correlations());
        self::assertNull($this->reread($request)->consumed_at);
    }

    /**
     * A `saml2` connection completes only at the assertion consumer service and
     * an `oidc` one only at the callback; anywhere else they are rejected with
     * `connection_unavailable` before their driver is asked. At its own
     * endpoint each reaches its driver, which names no request: the SAML driver
     * finds no response in an empty post, and the OIDC driver correlates
     * nothing until it is built. A protocol no driver is registered under
     * completes nowhere.
     *
     * @return void
     */
    public function testEachProtocolCompletesOnlyAtItsOwnEndpoint(): void
    {
        $saml = $this->makeConnection(['protocol' => 'saml2', 'enabled' => true]);
        $oidc = $this->makeConnection(['protocol' => 'oidc', 'enabled' => true]);
        $gone = $this->makeConnection(['protocol' => 'unregistered', 'enabled' => true]);

        self::assertResult(self::rejectedResult(FailureReason::CONNECTION_UNAVAILABLE), $this->completeAtCallback(connectionId: $saml->id));
        self::assertResult(self::rejectedResult(FailureReason::CONNECTION_UNAVAILABLE), $this->completeAtAssertionConsumerService(connectionId: $oidc->id));
        self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtAssertionConsumerService(connectionId: $saml->id));
        self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtCallback(connectionId: $oidc->id));
        self::assertResult(self::rejectedResult(FailureReason::CONNECTION_UNAVAILABLE), $this->completeAtCallback(connectionId: $gone->id));
        self::assertResult(self::rejectedResult(FailureReason::CONNECTION_UNAVAILABLE), $this->completeAtAssertionConsumerService(connectionId: $gone->id));
    }

    /**
     * A connection disabled after the start still consumes the request its
     * response names, then fails with `connection_unavailable`, redirected to
     * the application, without its driver being asked to validate.
     *
     * @return void
     */
    public function testADisabledConnectionConsumesItsRequestThenFails(): void
    {
        $request = $this->request();

        $this->connection->forceFill(['enabled' => false])->save();

        $result = $this->completeAtCallback();

        self::assertResult(self::failedResult(FailureReason::CONNECTION_UNAVAILABLE), $result);
        self::assertSame([], $this->driver->completions());
        self::assertSame([], $this->issuer->grants());

        $row = $this->reread($request);

        self::assertNotNull($row->consumed_at);
        self::assertSame('2026-11-01T09:30:00+00:00', $row->completed_at?->toIso8601String());
    }

    /**
     * A response that names a request started through another connection fails
     * with `connection_mismatch`, redirected to that request's application, as
     * it delivers, and consumes the request.
     *
     * @return void
     */
    public function testARequestOfAnotherConnectionFailsWithConnectionMismatch(): void
    {
        $other   = $this->makeVerifyingConnection();
        $request = $this->request(['application' => 'native'], $other);

        $result = $this->completeAtCallback();

        self::assertResult(self::failedResult(FailureReason::CONNECTION_MISMATCH, self::NATIVE_REDIRECT_URI, 'query'), $result);
        self::assertSame([], $this->driver->completions());

        $row = $this->reread($request);

        self::assertNotNull($row->consumed_at);
        self::assertNotNull($row->completed_at);
    }

    /**
     * Seconds after the start, against a ten-minute expiry, and whether the
     * completion then completes.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideExpiryBoundaries(): iterable
    {
        yield 'one second before' => [599, true];
        yield 'at the expiry' => [600, false];
        yield 'one second after' => [601, false];
    }

    /**
     * The request completes one second before its expiry, and fails with
     * `request_expired` at it and after it.
     *
     * @param  int  $seconds
     * @param  bool  $completes
     * @return void
     */
    #[DataProvider('provideExpiryBoundaries')]
    public function testTheRequestExpiresAtItsExpiry(int $seconds, bool $completes): void
    {
        $this->request();

        $this->clock->advance($seconds);

        $result = $this->completeAtCallback();

        if ($completes) {
            self::assertResult($this->completedResult(expiresAt: '2026-11-01T09:40:59+00:00'), $result);

            return;
        }

        self::assertResult(self::failedResult(FailureReason::REQUEST_EXPIRED), $result);
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * A response replayed once its request completed is rejected with
     * `request_unknown`, and issues nothing more.
     *
     * @return void
     */
    public function testAReplayIsRejected(): void
    {
        $this->request();

        self::assertTrue($this->completeAtCallback()->isCompleted());
        self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtCallback());
        self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtAssertionConsumerService());
        self::assertCount(1, $this->issuer->grants());
    }

    /**
     * A state no request has, a response with no state, and an unsolicited
     * response are rejected with `request_unknown`, consuming nothing.
     *
     * @return void
     */
    public function testAResponseNoRequestMatchesIsRejected(): void
    {
        $request = $this->request();

        self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtCallback('another-state'));
        self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtCallback(null));

        $this->driver->correlation = Correlation::unsolicited();

        self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtAssertionConsumerService());
        self::assertNull($this->reread($request)->consumed_at);
        self::assertSame([], $this->driver->completions());
    }

    /**
     * A response whose request's application is no longer registered is
     * rejected with `application_not_allowed`, with no target, its request
     * consumed and completed, so it is terminal, and nothing validated.
     *
     * @return void
     */
    public function testARequestOfAnUnregisteredApplicationIsRejectedAndTerminal(): void
    {
        $request = $this->request(['application' => 'retired']);

        self::assertResult(self::rejectedResult(FailureReason::APPLICATION_NOT_ALLOWED), $this->completeAtCallback());

        $row = $this->reread($request);

        self::assertSame('2026-11-01T09:30:00+00:00', $row->consumed_at?->toIso8601String());
        self::assertSame('2026-11-01T09:30:00+00:00', $row->completed_at?->toIso8601String());
        self::assertSame([], $this->driver->completions());
        self::assertSame([], $this->issuer->grants());
        self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtCallback());
    }

    /**
     * A response the driver refuses fails with the driver's reason, redirected
     * to the application, with its request consumed and completed.
     *
     * @return void
     */
    public function testARefusedResponseFailsWithItsReason(): void
    {
        $request = $this->request();

        $this->driver->refusal = FailureReason::SIGNATURE_INVALID;

        self::assertResult(self::failedResult(FailureReason::SIGNATURE_INVALID), $this->completeAtCallback());
        self::assertSame([], $this->issuer->grants());
        self::assertNotNull($this->reread($request)->completed_at);
    }

    /**
     * A `sign_in` resolved to no identity fails with `unlinked` while its
     * application does not allow unlinked handoffs.
     *
     * @return void
     */
    public function testAnUnlinkedSignInFails(): void
    {
        $this->request();

        $this->linked = null;

        self::assertResult(self::failedResult(FailureReason::UNLINKED), $this->completeAtCallback());
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * A `sign_in` resolved to no identity is handed off when its application
     * allows unlinked handoffs, with no linked identity, at its redirect URI,
     * in the query, and with its handoff lifetime.
     *
     * @return void
     */
    public function testAnUnlinkedSignInIsHandedOffWhenTheApplicationAllowsIt(): void
    {
        $this->request(['application' => 'native']);

        $this->linked = null;

        $result = $this->completeAtCallback();

        self::assertResult($this->completedResult(self::NATIVE_REDIRECT_URI, 'query', '2026-11-01T09:32:00+00:00'), $result);
        self::assertNull($this->issuer->soleGrant()->linkedIdentity);
    }

    /**
     * A required enforcement the connection satisfies completes; the
     * enforcement is asked for the connection's tenant and the request's
     * application.
     *
     * @return void
     */
    public function testARequiredEnforcementTheConnectionSatisfiesCompletes(): void
    {
        $this->request();
        $this->bindEnforcement(EnforcementPolicy::required('tenant-1', 'tenant-1', [$this->connection->id, 'another'], 'version-3'));

        $result = $this->completeAtCallback();

        self::assertResult($this->completedResult(), $result);
        self::assertSame(self::CHALLENGE, $this->issuer->soleGrant()->challenge->value);
        self::assertSame([['tenant-1', 'web']], $this->enforcementAsked);
    }

    /**
     * A required enforcement the connection does not satisfy fails with
     * `enforcement_unsatisfied`, and issues nothing.
     *
     * @return void
     */
    public function testARequiredEnforcementTheConnectionDoesNotSatisfyFails(): void
    {
        $this->request();
        $this->bindEnforcement(EnforcementPolicy::required('tenant-1', 'tenant-1', ['another'], 'version-3'));

        self::assertResult(self::failedResult(FailureReason::ENFORCEMENT_UNSATISFIED), $this->completeAtCallback());
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * An enforcement that requires nothing completes, whether it has a version
     * or none.
     *
     * @return void
     */
    public function testAnEnforcementNotRequiredCompletes(): void
    {
        $this->request();
        $this->bindEnforcement(EnforcementPolicy::notRequired('tenant-1', 'tenant-1', 'version-9'));

        self::assertTrue($this->completeAtCallback()->isCompleted());

        $second = 'the-protocol-state-of-the-second-request-02';

        $this->request(['reference' => str_repeat('S', 32), 'state_digest' => hash('sha256', $second)]);
        $this->bindEnforcement(EnforcementPolicy::notRequired('tenant-1', 'tenant-1'));

        self::assertTrue($this->completeAtCallback($second)->isCompleted());
        self::assertCount(2, $this->issuer->grants());
    }

    /**
     * An application whose policy no longer allows external sign-in when the
     * code would be issued fails with `application_not_allowed`, redirected to
     * it, and issues nothing.
     *
     * @return void
     */
    public function testAnApplicationNoLongerAllowedFailsAtIssuance(): void
    {
        $this->request();

        config()->set('sso.applications.web.external_sign_in', false);

        self::assertResult(self::failedResult(FailureReason::APPLICATION_NOT_ALLOWED), $this->completeAtCallback());
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * The provider's session deadline limits the application's session by
     * default, so the grant carries it as the session's latest end.
     *
     * @return void
     */
    public function testTheProviderDeadlineLimitsTheSessionByDefault(): void
    {
        $this->request();

        self::assertTrue($this->completeAtCallback()->isCompleted());
        self::assertSame('2026-11-01T18:00:00+00:00', $this->issuer->soleGrant()->sessionNotAfter?->toIso8601String());
    }

    /**
     * A deadline the contract ignores limits nothing, and the contract is asked
     * once; a result with no deadline never asks it.
     *
     * @return void
     */
    public function testAnIgnoredOrAbsentDeadlineLimitsNothing(): void
    {
        $this->bindDeadline(DeadlineEffect::IGNORED);
        $this->request();

        self::assertTrue($this->completeAtCallback()->isCompleted());
        self::assertNull($this->issuer->grants()[0]->sessionNotAfter);
        self::assertSame(1, $this->deadlineAsked);

        $second = 'the-protocol-state-of-the-second-request-02';

        $this->bindDeadline(DeadlineEffect::LIMITS_SESSION);
        $this->request(['reference' => str_repeat('S', 32), 'state_digest' => hash('sha256', $second)]);

        $this->driver->claims = new VerifiedClaims(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT, null, [], new AuthenticationContext);

        self::assertTrue($this->completeAtCallback($second)->isCompleted());
        self::assertNull($this->issuer->grants()[1]->sessionNotAfter);
        self::assertSame(0, $this->deadlineAsked);
    }

    /**
     * The grant of a `sign_in` is pinned field by field: the verified result,
     * the request's challenge, an expiry of the application's lifetime from
     * now, the linked identity, no identity or session, no enforcement version
     * while enforcement is off, and the deadline.
     *
     * @return void
     */
    public function testTheGrantIsPinnedFieldByField(): void
    {
        $this->request();

        self::assertTrue($this->completeAtCallback()->isCompleted());

        $grant  = $this->issuer->soleGrant();
        $pinned = $grant->result->toArray();

        // MySQL keeps a JSON object's keys in its own order, not as written.
        ksort($pinned['attributes']);

        self::assertSame([
            'issuer'                 => VerifyingDriver::ISSUER,
            'subject'                => VerifyingDriver::SUBJECT,
            'name_id_format'         => null,
            'connection_id'          => $this->connection->id,
            'tenant_id'              => 'tenant-1',
            'protocol'               => VerifyingDriver::NAME,
            'application'            => 'web',
            'purpose'                => 'sign_in',
            'request_reference'      => self::REFERENCE,
            'attributes'             => ['email' => 'person@example.com', 'given_name' => 'Ada', 'groups' => ['staff', 'admins']],
            'email_domain_verified'  => false,
            'authentication_context' => [
                'authenticated_at'          => '2026-11-01T09:29:00.000000Z',
                'methods'                   => ['pwd'],
                'context_class'             => null,
                'provider_session_id'       => 'provider-session-1',
                'provider_session_deadline' => '2026-11-01T18:00:00.000000Z',
            ],
            'linking_email' => null,
        ], $pinned);

        self::assertSame(self::CHALLENGE, $grant->challenge->value);
        self::assertSame('2026-11-01T09:31:00+00:00', $grant->expiresAt->toIso8601String());
        self::assertSame(['type' => 'App\Models\User', 'id' => '42'], $grant->linkedIdentity?->jsonSerialize());
        self::assertNull($grant->identity);
        self::assertNull($grant->sessionId);
        self::assertSame('2026-11-01T18:00:00+00:00', $grant->sessionNotAfter?->toIso8601String());
    }

    /**
     * A `link` grant names the identity the request was started for, beside the
     * identity the result's link resolved to, and no session; an unlinked
     * `link` is handed off too.
     *
     * @return void
     */
    public function testALinkGrantNamesTheIdentityItWasStartedFor(): void
    {
        $this->request(['purpose' => 'link', 'identity_type' => 'App\Models\User', 'identity_id' => '7']);

        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Linker::class, new DelegatingLinkStorage(app(LinkStore::class), LinkResolution::absent()));
        $this->linked = null;

        $result = $this->completeAtCallback();

        self::assertResult($this->completedResult(), $result);

        $grant = $this->issuer->soleGrant();

        self::assertSame('link', $grant->result->purpose->value);
        self::assertSame(['type' => 'App\Models\User', 'id' => '7'], $grant->identity?->jsonSerialize());
        self::assertNull($grant->linkedIdentity);
        self::assertNull($grant->sessionId);
    }

    /**
     * A `reauthenticate` grant names the identity and the session the request
     * was started for.
     *
     * @return void
     */
    public function testAReauthenticationGrantNamesTheIdentityAndTheSession(): void
    {
        $this->request(['purpose' => 'reauthenticate', 'identity_type' => 'App\Models\User', 'identity_id' => '42', 'session_id' => 'session-1']);

        $result = $this->completeAtCallback();

        self::assertResult($this->completedResult(), $result);

        $grant = $this->issuer->soleGrant();

        self::assertSame('reauthenticate', $grant->result->purpose->value);
        self::assertSame(['type' => 'App\Models\User', 'id' => '42'], $grant->identity?->jsonSerialize());
        self::assertSame(['type' => 'App\Models\User', 'id' => '42'], $grant->linkedIdentity?->jsonSerialize());
        self::assertSame('session-1', $grant->sessionId);
    }

    /**
     * A full limit per connection, and one per IP address, are `rate_limited`
     * with the wait to the end of the window, before anything is read or
     * consumed. The attempt a full connection limit refused gives the IP
     * address's attempt back, so the address has made one.
     *
     * @return void
     */
    public function testAFullLimitIsRateLimited(): void
    {
        $request = $this->request();

        config()->set('sso.rate_limits.completion.per_connection', ['max' => 1, 'decay_seconds' => 60]);

        self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtCallback('another-state'));
        self::assertResult(self::rateLimitedResult(60), $this->completeAtCallback());

        config()->set('sso.rate_limits.completion.per_connection', ['max' => 600, 'decay_seconds' => 60]);
        config()->set('sso.rate_limits.completion.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        self::assertResult(self::rateLimitedResult(60), $this->completeAtCallback(connectionId: self::UNKNOWN_ID));

        self::assertSame(1, $this->driver->correlations());
        self::assertNull($this->reread($request)->consumed_at);
    }

    /**
     * A database error propagates as a server error, never as a failure or a
     * rejection.
     *
     * @return void
     */
    public function testADatabaseErrorPropagates(): void
    {
        $this->request();

        Schema::connection(StorageConnection::name())->dropIfExists(StorageConnection::table('authorization_requests.table'));

        $this->expectException(QueryException::class);

        $this->completeAtCallback();
    }

    /**
     * Assert the result is exactly the one described.
     *
     * @param  array<string, mixed>  $expected
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return void
     */
    private static function assertResult(array $expected, CompletionResult $result): void
    {
        self::assertSame($expected, [
            'status'       => $result->status->value,
            'reason'       => $result->reason?->value,
            'redirect_uri' => $result->redirectUri,
            'delivery'     => $result->delivery?->value,
            'reference'    => $result->reference?->value,
            'handoff'      => $result->handoff?->code->reveal(),
            'expires_at'   => $result->handoff?->expiresAt->toIso8601String(),
            'retry_after'  => $result->retryAfter,
            'start_url'    => $result->startUrl,
        ]);
    }

    /**
     * A completed result, with the last code issued.
     *
     * @param  string  $redirectUri
     * @param  string  $delivery
     * @param  string  $expiresAt
     * @return array<string, mixed>
     */
    private function completedResult(string $redirectUri = self::REDIRECT_URI, string $delivery = 'fragment', string $expiresAt = '2026-11-01T09:31:00+00:00'): array
    {
        $issued = $this->issuer->issued();

        return [
            'status'       => 'completed',
            'reason'       => null,
            'redirect_uri' => $redirectUri,
            'delivery'     => $delivery,
            'reference'    => self::REFERENCE,
            'handoff'      => $issued === [] ? 'none issued' : $issued[array_key_last($issued)]->code->reveal(),
            'expires_at'   => $expiresAt,
            'retry_after'  => null,
            'start_url'    => null,
        ];
    }

    /**
     * A failed result.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  string  $redirectUri
     * @param  string  $delivery
     * @return array<string, mixed>
     */
    private static function failedResult(FailureReason $reason, string $redirectUri = self::REDIRECT_URI, string $delivery = 'fragment'): array
    {
        return [
            'status'       => 'failed',
            'reason'       => $reason->value,
            'redirect_uri' => $redirectUri,
            'delivery'     => $delivery,
            'reference'    => self::REFERENCE,
            'handoff'      => null,
            'expires_at'   => null,
            'retry_after'  => null,
            'start_url'    => null,
        ];
    }

    /**
     * A rejected result.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return array<string, mixed>
     */
    private static function rejectedResult(FailureReason $reason): array
    {
        return [
            'status'       => 'rejected',
            'reason'       => $reason->value,
            'redirect_uri' => null,
            'delivery'     => null,
            'reference'    => null,
            'handoff'      => null,
            'expires_at'   => null,
            'retry_after'  => null,
            'start_url'    => null,
        ];
    }

    /**
     * A rate limited result.
     *
     * @param  int  $retryAfter
     * @return array<string, mixed>
     */
    private static function rateLimitedResult(int $retryAfter): array
    {
        return [
            'status'       => 'rate_limited',
            'reason'       => 'rate_limited',
            'redirect_uri' => null,
            'delivery'     => null,
            'reference'    => null,
            'handoff'      => null,
            'expires_at'   => null,
            'retry_after'  => $retryAfter,
            'start_url'    => null,
        ];
    }

    /**
     * Complete at the callback, with the state in the query unless none is
     * given.
     *
     * @param  ?string  $state
     * @param  ?string  $connectionId
     * @param  string  $method
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function completeAtCallback(?string $state = self::STATE, ?string $connectionId = null, string $method = 'GET'): CompletionResult
    {
        $request = new CompletionRequest($method, $state === null ? '' : 'state=' . $state, []);

        return $this->service()->callback($connectionId ?? $this->connection->id, $request);
    }

    /**
     * Complete at the assertion consumer service, with the state posted.
     *
     * @param  ?string  $connectionId
     * @param  string  $method
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function completeAtAssertionConsumerService(?string $connectionId = null, string $method = 'POST'): CompletionResult
    {
        $request = new CompletionRequest($method, '', ['state' => self::STATE]);

        return $this->service()->assertionConsumerService($connectionId ?? $this->connection->id, $request);
    }

    /**
     * The completion service, resolved for this request.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionService
     */
    private function service(): CompletionService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(CompletionService::class);
    }

    /**
     * Store a `sign_in` request for `web` through the connection, started with
     * the state, the reference and the challenge, unless the attributes say
     * otherwise.
     *
     * @param  array<string, mixed>  $attributes
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function request(array $attributes = [], ?Connection $connection = null): AuthorizationRequest
    {
        return $this->makeAuthorizationRequest($connection ?? $this->connection, $attributes + [
            'reference'         => self::REFERENCE,
            'state_digest'      => hash('sha256', self::STATE),
            'handoff_challenge' => self::CHALLENGE,
            'expected_issuer'   => VerifyingDriver::ISSUER,
            'code_verifier'     => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-completed-request-0'),
        ]);
    }

    /**
     * Make a usable connection over the verifying driver, mapping the email,
     * the given name and the groups.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function makeVerifyingConnection(): Connection
    {
        return $this->makeConnection([
            'protocol'          => VerifyingDriver::NAME,
            'enabled'           => true,
            'settings'          => ['issuer' => VerifyingDriver::ISSUER],
            'attribute_mapping' => ['email' => 'mail', 'given_name' => 'given', 'groups' => 'memberOf'],
        ]);
    }

    /**
     * The request, read again.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function reread(AuthorizationRequest $request): AuthorizationRequest
    {
        return AuthorizationRequest::query()->whereKey($request->id)->sole();
    }

    /**
     * Bind an enforcement contract that answers the policy, recording what it
     * is asked.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @return void
     */
    private function bindEnforcement(EnforcementPolicy $policy): void
    {
        $answer = function (string $tenantId, string $application) use ($policy): EnforcementPolicy {
            $this->enforcementAsked[] = [$tenantId, $application];

            return $policy;
        };

        $this->app?->instance(Enforcement::class, new readonly class ($answer) implements Enforcement {
            /**
             * Constructor.
             *
             * @param  \Closure(string, string): \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $answer
             */
            public function __construct(

                /** What every question is answered. */
                private \Closure $answer,
            ) {}

            /**
             * The policy given.
             *
             * @param  string  $tenantId
             * @param  string  $application
             * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
             */
            #[\Override]
            public function policy(string $tenantId, string $application): EnforcementPolicy
            {
                return ($this->answer)($tenantId, $application);
            }
        });
    }

    /**
     * Bind a deadline contract that answers the effect, counting from zero how
     * often it is asked.
     *
     * @param  \SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect  $effect
     * @return void
     */
    private function bindDeadline(DeadlineEffect $effect): void
    {
        $this->deadlineAsked = 0;

        $answer = function () use ($effect): DeadlineEffect {
            $this->deadlineAsked++;

            return $effect;
        };

        $this->app?->instance(ProviderSessionDeadline::class, new readonly class ($answer) implements ProviderSessionDeadline {
            /**
             * Constructor.
             *
             * @param  \Closure(): \SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect  $answer
             */
            public function __construct(

                /** What every question is answered. */
                private \Closure $answer,
            ) {}

            /**
             * The effect given.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect
             */
            #[\Override]
            public function effect(VerifiedResult $result): DeadlineEffect
            {
                unset($result);

                return ($this->answer)();
            }
        });
    }

    /**
     * A linking contract that answers through the closure.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Results\VerifiedResult): ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $resolve
     * @return \SineMacula\Laravel\Sso\Contracts\Linker
     */
    private static function linker(\Closure $resolve): Linker
    {
        return new readonly class ($resolve) implements Linker {
            /**
             * Constructor.
             *
             * @param  \Closure(\SineMacula\Laravel\Sso\Results\VerifiedResult): ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $resolve
             */
            public function __construct(

                /** What every result resolves to. */
                private \Closure $resolve,
            ) {}

            /**
             * What the closure answers.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result): LinkResolution
            {
                return ExampleLinks::resolution(($this->resolve)($result));
            }
        };
    }

    /**
     * The shipped migration of the file.
     *
     * @param  string  $file
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function migration(string $file): Migration
    {
        return require dirname(__DIR__, 3) . $file;
    }
}
