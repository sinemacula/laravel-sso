<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
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
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Http\ClientContext;
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
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
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
 * Feature tests for completing a flow at the callback and assertion consumer.
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
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

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

    /** @var \SineMacula\Laravel\Sso\Http\ClientContext The client every completion arrives from. */
    private ClientContext $client;

    /**
     * Bind a clock, the issuer, a linker and the client; add a connection.
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
        $this->client = new ClientContext('203.0.113.7', 'Example/1.0');

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

        $this->usePackageTables();

        $this->connection = $this->makeVerifyingConnection();
    }

    /**
     * A verified callback completes with a handoff at the redirect URI.
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
     * An assertion posted to the assertion consumer service completes.
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
     * The callback takes `GET` only and rejects any other method first.
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
     * An unknown connection is rejected with `connection_unavailable`.
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
     * Each protocol completes only at its own endpoint.
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
     * A disabled connection consumes its request, then fails.
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
     * A request of another connection fails with `connection_mismatch`.
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
     * Seconds after the start against a ten-minute expiry, and if it completes.
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
     * The request expires at its expiry.
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
     * A replay is rejected with `request_unknown`.
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
     * A response no request matches is rejected, consuming nothing.
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
     * A request of an unregistered application is rejected and terminal.
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
     * A refused response fails with the driver's reason.
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
     * An unlinked `sign_in` fails unless the application allows it.
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
     * An unlinked `sign_in` is handed off when the application allows it.
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
     * A required enforcement the connection satisfies completes.
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
     * A required enforcement the connection does not satisfy fails.
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
     * An enforcement that requires nothing completes.
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
     * An application no longer allowed fails at issuance.
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
     * The provider's deadline limits the session by default.
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
     * An ignored or absent deadline limits nothing.
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
     * The grant of a `sign_in` is pinned field by field.
     *
     * @return void
     */
    public function testTheGrantIsPinnedFieldByField(): void
    {
        $this->request();

        self::assertTrue($this->completeAtCallback()->isCompleted());

        $grant      = $this->issuer->soleGrant();
        $pinned     = $grant->result->toArray();
        $attributes = $pinned['attributes'];

        self::assertIsArray($attributes);

        // MySQL keeps a JSON object's keys in its own order, not as written.
        ksort($attributes);

        $pinned['attributes'] = $attributes;

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
     * A `link` grant names the identity it was started for.
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
     * A `reauthenticate` grant names its identity and session.
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
     * A full connection or address limit is `rate_limited` before any read.
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
     * Both endpoints share one count, taken before the method is checked.
     *
     * @return void
     */
    public function testBothEndpointsShareOneCountTakenBeforeTheMethod(): void
    {
        config()->set('sso.rate_limits.completion.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtCallback(method: 'POST'));
        self::assertResult(self::rateLimitedResult(60), $this->completeAtAssertionConsumerService());

        $this->client = new ClientContext('198.51.100.9', 'Example/1.0');

        self::assertResult(self::rejectedResult(FailureReason::REQUEST_UNKNOWN), $this->completeAtAssertionConsumerService(method: 'GET'));
    }

    /**
     * Rows of `[endpoint, method, connection, reason]` before the steps.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint, 1: string, 2: ?string, 3: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusalsBeforeTheSteps(): iterable
    {
        $acs      = CompletionEndpoint::ASSERTION_CONSUMER_SERVICE;
        $callback = CompletionEndpoint::CALLBACK;

        yield 'rate limited at the assertion consumer service' => [$acs, 'POST', null, FailureReason::RATE_LIMITED];
        yield 'rate limited at the callback' => [$callback, 'GET', null, FailureReason::RATE_LIMITED];
        yield 'another method at the assertion consumer service' => [$acs, 'GET', null, FailureReason::REQUEST_UNKNOWN];
        yield 'another method at the callback' => [$callback, 'POST', null, FailureReason::REQUEST_UNKNOWN];
        yield 'an unknown connection at the assertion consumer service' => [$acs, 'POST', self::UNKNOWN_ID, FailureReason::CONNECTION_UNAVAILABLE];
        yield 'an unknown connection at the callback' => [$callback, 'GET', self::UNKNOWN_ID, FailureReason::CONNECTION_UNAVAILABLE];
        yield 'an OIDC connection at the assertion consumer service' => [$acs, 'POST', 'oidc', FailureReason::CONNECTION_UNAVAILABLE];
    }

    /**
     * Each refusal before the steps reports the endpoint's flow and the client.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint  $endpoint
     * @param  string  $method
     * @param  ?string  $connection
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusalsBeforeTheSteps')]
    public function testEachRefusalBeforeTheStepsReportsTheEndpointsFlowAndTheClient(CompletionEndpoint $endpoint, string $method, ?string $connection, FailureReason $reason): void
    {
        if ($reason === FailureReason::RATE_LIMITED) {
            config()->set('sso.rate_limits.completion.per_ip', ['max' => 1, 'decay_seconds' => 60]);
            $this->service()->complete($endpoint, self::UNKNOWN_ID, new CompletionRequest($method, '', []), $this->client);
        }

        $connectionId = match ($connection) {
            null    => $this->connection->id,
            'oidc'  => $this->makeConnection(['protocol' => 'oidc', 'enabled' => true])->id,
            default => $connection,
        };

        $this->app?->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => 'Served/1.0']));
        $this->startRecordingEvents();

        $this->service()->complete($endpoint, $connectionId, new CompletionRequest($method, 'state=' . self::STATE, ['state' => self::STATE]), $this->client);

        $failure = $this->assertExactlyOneFailure($endpoint === CompletionEndpoint::CALLBACK ? Flow::CALLBACK : Flow::ASSERTION, $reason);

        self::assertSame(['203.0.113.7', 'Example/1.0'], [$failure->context()->ip, $failure->context()->userAgent]);
        self::assertSame(0, $this->driver->correlations());
    }

    /**
     * A client with no address counts against the connection alone.
     *
     * @return void
     */
    public function testAClientWithNoAddressCountsAgainstTheConnectionAlone(): void
    {
        config()->set('sso.rate_limits.completion.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $this->client = new ClientContext(null, null);

        self::assertResult(self::rejectedResult(FailureReason::CONNECTION_UNAVAILABLE), $this->completeAtCallback(connectionId: self::UNKNOWN_ID));

        $this->startRecordingEvents();

        self::assertResult(self::rejectedResult(FailureReason::CONNECTION_UNAVAILABLE), $this->completeAtCallback(connectionId: self::UNKNOWN_ID));

        $failure = $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::CONNECTION_UNAVAILABLE);

        self::assertSame([null, null], [$failure->context()->ip, $failure->context()->userAgent]);
    }

    /**
     * A database error propagates as a server error.
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
     * Complete at the callback, with the state in the query if given.
     *
     * @param  ?string  $state
     * @param  ?string  $connectionId
     * @param  string  $method
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function completeAtCallback(?string $state = self::STATE, ?string $connectionId = null, string $method = 'GET'): CompletionResult
    {
        $request = new CompletionRequest($method, $state === null ? '' : 'state=' . $state, []);

        return $this->service()->complete(CompletionEndpoint::CALLBACK, $connectionId ?? $this->connection->id, $request, $this->client);
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

        return $this->service()->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $connectionId ?? $this->connection->id, $request, $this->client);
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
     * Store a `sign_in` request for `web` unless the attributes say otherwise.
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
     * Make a usable connection over the verifying driver.
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
     * Bind an enforcement contract answering the policy and recording calls.
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
     * Bind a deadline contract answering the effect and counting calls.
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
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
            {
                return ExampleLinks::resolution(($this->resolve)($result));
            }
        };
    }
}
