<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\StartingAFlow;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * Integration tests for the examples of `docs/guides/starting-a-flow.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(StartResult::class)]
final class StartingAFlowExampleTest extends ExampleTestCase
{
    /** @var string The route the guide's application starts a flow on. */
    private const string ROUTE = '/auth/sso/authorization-requests';

    /** @var string The S256 challenge of a client's own verifier (RFC 7636, appendix B). */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var string The address of an office behind one NAT address. */
    private const string OFFICE = '203.0.113.7';

    /** @var string The address of another client. */
    private const string ELSEWHERE = '198.51.100.9';

    /** @var string A connection id no connection has. */
    private const string UNKNOWN_CONNECTION = '01JBZZZZZZZZZZZZZZZZZZZZZZ';

    /** @var string The session the caller signed in on. */
    private const string SESSION = 'session-1';

    /** @var string A public reference: 32 base64url characters. */
    private const string REFERENCE = '/^[A-Za-z0-9_-]{32}$/';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts the provider. */
    private string $connectionId;

    /**
     * Serve the guide's route, and make the connection it starts through.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Route::group([], __DIR__ . '/routes.php');

        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);
    }

    /**
     * The service counts the client it is given, not the request being served.
     *
     * @return void
     */
    public function testTheServiceCountsTheClientItIsGiven(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $office   = ClientContext::fromRequest(Request::create(self::ROUTE, 'POST', server: ['REMOTE_ADDR' => self::OFFICE]));
        $requests = self::resolved();

        self::assertTrue($requests->start(self::APPLICATION, Purpose::SIGN_IN, $this->connectionId, $office)->isStarted());

        $limited = $requests->start(self::APPLICATION, Purpose::SIGN_IN, $this->connectionId, $office);

        self::assertTrue($limited->isRateLimited());
        self::assertSame(60, $limited->retryAfter);

        $elsewhere = ClientContext::fromRequest(Request::create(self::ROUTE, 'POST', server: ['REMOTE_ADDR' => self::ELSEWHERE]));

        self::assertTrue(self::resolved()->start(self::APPLICATION, Purpose::SIGN_IN, $this->connectionId, $elsewhere)->isStarted());
    }

    /**
     * A started answer carries a generated verifier only when no challenge was
     * sent.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheRouteStartsASignIn(): void
    {
        $generated = self::bodyOf($this->startOnRoute(['application' => self::APPLICATION, 'connection' => $this->connectionId]), 200);

        self::assertEqualsCanonicalizing(['reference', 'navigation', 'verifier'], array_keys($generated));
        self::assertMatchesRegularExpression(self::REFERENCE, self::stringOf($generated, 'reference'));
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', self::stringOf($generated, 'verifier'));

        $navigation = $generated['navigation'];

        self::assertIsArray($navigation);
        self::assertSame('redirect', $navigation['type'] ?? null);
        self::assertSame(FakeOpenIdProvider::CLIENT_ID, $this->provider->authorize(self::stringOf($navigation, 'url'))->parameter('client_id'));

        $challenged = self::bodyOf($this->startOnRoute(['application' => self::APPLICATION, 'connection' => $this->connectionId, 'code_challenge' => self::CHALLENGE]), 200);

        self::assertEqualsCanonicalizing(['reference', 'navigation'], array_keys($challenged));
        self::assertMatchesRegularExpression(self::REFERENCE, self::stringOf($challenged, 'reference'));
        self::assertNotSame($generated['reference'], $challenged['reference']);
    }

    /**
     * Each refusal is answered `400` with its reason and one `FlowFailed`.
     *
     * @return void
     */
    public function testTheRouteAnswersARefusalWithItsReason(): void
    {
        $failed = $this->failures();

        $application = self::bodyOf($this->startOnRoute(['application' => 'kiosk', 'connection' => $this->connectionId]), 400);
        $challenge   = self::bodyOf($this->startOnRoute(['application' => self::APPLICATION, 'connection' => $this->connectionId, 'code_challenge' => 'plain']), 400);
        $connection  = self::bodyOf($this->startOnRoute(['application' => self::APPLICATION, 'connection' => self::UNKNOWN_CONNECTION]), 400);

        self::assertSame(['error' => 'application_not_allowed'], $application);
        self::assertSame(['error' => 'challenge_invalid'], $challenge);
        self::assertSame(['error' => 'connection_unavailable'], $connection);
        self::assertSame(
            [FailureReason::APPLICATION_NOT_ALLOWED, FailureReason::CHALLENGE_INVALID, FailureReason::CONNECTION_UNAVAILABLE],
            array_map(static fn (FlowFailed $event): FailureReason => $event->reason, $failed->getArrayCopy()),
        );
    }

    /**
     * A full limit is answered `429` with the wait in the body and
     * `Retry-After`.
     *
     * @return void
     */
    public function testTheRouteAnswersAFullLimitWithItsWait(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        self::bodyOf($this->startOnRoute(['application' => self::APPLICATION, 'connection' => $this->connectionId]), 200);

        $limited = $this->startOnRoute(['application' => self::APPLICATION, 'connection' => $this->connectionId]);

        self::assertEquals(['error' => 'rate_limited', 'retry_after' => 60], self::bodyOf($limited, 429));
        self::assertSame('60', $limited->headers->get('Retry-After'));
    }

    /**
     * A fresh, signed-in caller starts a `link` and a `reauthenticate`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testALinkAndAReauthenticationStartForTheCaller(): void
    {
        $user  = $this->signedIn();
        $asked = count($this->freshness->asked());

        [$linking, $reauthenticating] = self::startForCaller([
            'user'           => $user,
            'connection'     => $this->connectionId,
            'code_challenge' => self::CHALLENGE,
            'session'        => self::SESSION,
        ]);

        self::assertTrue($linking->isStarted());
        self::assertTrue($reauthenticating->isStarted());
        self::assertNull($linking->verifier);
        self::assertNull($reauthenticating->verifier);
        self::assertNotSame($linking->reference?->value, $reauthenticating->reference?->value);
        self::assertSame(FakeOpenIdProvider::CLIENT_ID, $this->provider->authorize($linking)->parameter('client_id'));
        self::assertSame('login', $this->provider->authorize($reauthenticating)->parameter('prompt'));
        self::assertSame([FreshnessOperation::LINK_CREATE], array_column(array_slice($this->freshness->asked(), $asked), 'operation'));
    }

    /**
     * A stale caller's `link` and an ineligible session's `reauthenticate` are
     * refused.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEachIsRefusedWithoutItsCondition(): void
    {
        $user = $this->signedIn();

        $this->freshness->staleFor(FreshnessOperation::LINK_CREATE);

        [$linking, $reauthenticating] = self::startForCaller([
            'user'           => $user,
            'connection'     => $this->connectionId,
            'code_challenge' => self::CHALLENGE,
            'session'        => 'session-2',
        ]);

        self::assertTrue($linking->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $linking->reason);
        self::assertNull($linking->navigation);
        self::assertTrue($reauthenticating->isRefused());
        self::assertSame(FailureReason::SESSION_INELIGIBLE, $reauthenticating->reason);
        self::assertSame(['error' => 'session_ineligible'], $reauthenticating->body());
    }

    /**
     * A caller with an empty session id throws `InvalidArgumentException`.
     *
     * @return void
     */
    public function testAnEmptySessionIdIsAMistake(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('A session id is 1 to %d bytes.', Caller::MAX_SESSION_ID_LENGTH));

        self::startForCaller([
            'user'           => new User(['id' => 'person-1']),
            'connection'     => $this->connectionId,
            'code_challenge' => self::CHALLENGE,
            'session'        => '',
        ]);
    }

    /**
     * Link the application's user and sign them in on the session.
     *
     * @return \Tests\Integration\Examples\StartingAFlow\User
     *
     * @throws \Random\RandomException
     */
    private function signedIn(): User
    {
        $user = new User(['id' => 'person-1']);

        $this->linkThroughFlow($this->provider, $this->connectionId, new IdentityReference($user->getMorphClass(), (string) $user->getKey()));

        self::assertTrue($this->signInThroughFlow($this->provider, $this->connectionId, self::SESSION)->isAdmitted());

        return $user;
    }

    /**
     * Post a start to the guide's route from the office's address.
     *
     * @param  array<string, string>  $payload
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function startOnRoute(array $payload): TestResponse
    {
        return $this->withServerVariables(['REMOTE_ADDR' => self::OFFICE])->postJson(self::ROUTE, $payload);
    }

    /**
     * Every `FlowFailed` reported from now on.
     *
     * @return \ArrayObject<int, \SineMacula\Laravel\Sso\Events\FlowFailed>
     */
    private function failures(): \ArrayObject
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\FlowFailed> $failed */
        $failed = new \ArrayObject;

        Event::listen(FlowFailed::class, static function (FlowFailed $event) use ($failed): void {
            $failed->append($event);
        });

        return $failed;
    }

    /**
     * The service the guide resolves for each request.
     *
     * @return \SineMacula\Laravel\Sso\Flows\AuthorizationRequestService
     */
    private static function resolved(): AuthorizationRequestService
    {
        $requests = require __DIR__ . '/service.php';

        self::assertInstanceOf(AuthorizationRequestService::class, $requests);

        return $requests;
    }

    /**
     * The guide's `link` and `reauthenticate` starts for the caller.
     *
     * @param  array{user: \Tests\Integration\Examples\StartingAFlow\User, connection: string, code_challenge: string, session: string}  $input
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: \SineMacula\Laravel\Sso\Flows\StartResult}
     */
    private static function startForCaller(array $input): array
    {
        $input['client'] = Clients::browser();

        $results = require __DIR__ . '/caller.php';

        self::assertIsArray($results);
        self::assertCount(2, $results);
        self::assertContainsOnlyInstancesOf(StartResult::class, $results);

        /** @var array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: \SineMacula\Laravel\Sso\Flows\StartResult} $results */
        return $results;
    }

    /**
     * The string under the key of a decoded body.
     *
     * @param  array<array-key, mixed>  $body
     * @param  string  $key
     * @return string
     */
    private static function stringOf(array $body, string $key): string
    {
        $value = $body[$key] ?? null;

        self::assertIsString($value);

        return $value;
    }

    /**
     * The start response's body, asserting its status and that it is never
     * cached.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  int  $status
     * @return array<array-key, mixed>
     */
    private static function bodyOf(TestResponse $response, int $status): array
    {
        $response->assertStatus($status);

        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));

        $body = $response->json();

        self::assertIsArray($body);

        return $body;
    }
}
