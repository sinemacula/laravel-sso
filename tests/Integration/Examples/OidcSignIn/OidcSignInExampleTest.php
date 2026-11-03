<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OidcSignIn;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/oidc-sign-in.md` (SSO-5.4, SSO-5.10, SSO-2.4,
 * SSO-12.5), on the shared example harness, through a connection that sends
 * `max_age=3600` and an extra `prompt=select_account`: the sign-in start
 * endpoint and the reauthentication start, each run as the application runs it,
 * with the client's own PKCE challenge. Each asserts its outcome and a refusal:
 * a sign-in start answers `200` and sends the browser to the provider with the
 * parameters the guide lists, in its order, and never the client's challenge,
 * and the flow it starts signs the person in; an authorisation endpoint whose
 * own query names `state` answers `400` `connection_unavailable`, while one
 * whose query names nothing the request sets keeps it. A reauthentication sends
 * `max_age=0` and `prompt=login` in place of the connection's own and renews
 * the session; one for a session the person is not signed in on is refused
 * `session_ineligible`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(StartResult::class)]
final class OidcSignInExampleTest extends ExampleTestCase
{
    /** @var string The client's own PKCE verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var string Its S256 challenge, which the client sends with the start. */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var string The session the person signs in on. */
    private const string SESSION = 'session-1';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /**
     * Make the tenant's OIDC connection, sending a `max_age` and an extra
     * `prompt` of its own, and link the person through it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider, ['max_age' => 3600, 'extra_parameters' => ['prompt' => 'select_account']]);
        $this->person       = new IdentityReference('App\Models\User', 'person-1');

        $this->linkThroughFlow($this->provider, $this->connectionId, $this->person);
    }

    /**
     * The start answers `200`, `no-store`, with a `redirect` navigation and no
     * verifier, since the client sent its challenge. The provider is sent the
     * guide's parameters in the guide's order, the connection's `max_age` and
     * its extra `prompt` last, and a challenge of the package's own verifier,
     * not the client's; `state` is not the request's public reference. The
     * provider's answer, redeemed with the client's verifier, signs the person
     * in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASignInStartSendsTheBrowserToTheProvider(): void
    {
        $body  = self::bodyOf(self::startSigningIn(['connection' => $this->connectionId, 'code_challenge' => self::CHALLENGE]), 200);
        $grant = $this->provider->authorize(self::navigationUrl($body));

        self::assertArrayNotHasKey('verifier', $body);
        self::assertSame([
            'response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method', 'max_age', 'prompt',
        ], array_keys($grant->parameters()));
        self::assertSame([
            'response_type'         => 'code',
            'client_id'             => FakeOpenIdProvider::CLIENT_ID,
            'redirect_uri'          => 'https://sp.example.test/auth/sso/connections/' . $this->connectionId . '/callback',
            'scope'                 => 'openid email profile',
            'code_challenge_method' => 'S256',
            'max_age'               => '3600',
            'prompt'                => 'select_account',
        ], array_diff_key($grant->parameters(), array_flip(['state', 'nonce', 'code_challenge'])));
        self::assertNotSame(self::CHALLENGE, $grant->parameter('code_challenge'));
        self::assertNotSame($body['reference'] ?? null, $grant->parameter('state'));

        $redirect = $this->completeAt($grant);
        $signedIn = $this->admit(Purpose::SIGN_IN, $redirect);

        self::assertSame($body['reference'] ?? null, $redirect->reference);
        self::assertTrue($signedIn->isAdmitted());
        self::assertEquals($this->person, $signedIn->linkedIdentity);
    }

    /**
     * An authorisation endpoint's own query is kept ahead of the request's
     * parameters; one that names `state`, in another case, refuses the start
     * with `400` and `connection_unavailable`, and no navigation, rather than
     * sending it twice.
     *
     * @return void
     */
    public function testAnEndpointQueryNamingARequestParameterRefusesTheStart(): void
    {
        $kept    = $this->connectionAt('https://kept.example.test', '?tenant=acme');
        $refused = $this->connectionAt('https://refused.example.test', '?tenant=acme&State=fixed');

        $started = self::bodyOf(self::startSigningIn(['connection' => $kept, 'code_challenge' => self::CHALLENGE]), 200);

        self::assertStringStartsWith('https://kept.example.test/authorize?tenant=acme&response_type=code&', self::navigationUrl($started));

        $body = self::bodyOf(self::startSigningIn(['connection' => $refused, 'code_challenge' => self::CHALLENGE]), 400);

        self::assertSame(['error' => FailureReason::CONNECTION_UNAVAILABLE->value], $body);
    }

    /**
     * An hour after signing in, a reauthentication of the person's session is
     * started with the client's challenge and no verifier of the package's;
     * the provider is sent `max_age=0` and `prompt=login` in place of the
     * connection's `max_age` and extra `prompt`, which is left out; and its
     * answer, admitted with the client's verifier, renews that session to when
     * the provider authenticated the person again.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAReauthenticationForcesFreshAuthentication(): void
    {
        $this->signInThroughFlow($this->provider, $this->connectionId, self::SESSION);
        $this->clock->advance(3600);

        $start = self::startReauthenticating(['connection' => $this->connectionId, 'code_challenge' => self::CHALLENGE, 'identity' => $this->person, 'session' => self::SESSION]);
        $url   = (string) $start->navigation?->url();
        $grant = $this->provider->authorize($url);

        self::assertTrue($start->isStarted());
        self::assertNull($start->verifier);
        self::assertSame(['0', 'login'], [$grant->parameter('max_age'), $grant->parameter('prompt')]);
        self::assertSame(1, substr_count($url, 'prompt='));
        self::assertStringNotContainsString('select_account', $url);

        $renewed = $this->admit(Purpose::REAUTHENTICATE, $this->completeAt($grant));

        self::assertTrue($renewed->isAdmitted());
        self::assertSame(self::SESSION, $renewed->sessionId);
        self::assertSame('2026-11-01T10:30:00Z', $this->sessions->authenticatedAt(self::SESSION)?->toIso8601ZuluString());
    }

    /**
     * A reauthentication of a session the person is not signed in on is refused
     * `session_ineligible`, sending the browser nowhere.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAReauthenticationOfAnotherSessionIsRefused(): void
    {
        $this->signInThroughFlow($this->provider, $this->connectionId, self::SESSION);

        $refused = self::startReauthenticating(['connection' => $this->connectionId, 'code_challenge' => self::CHALLENGE, 'identity' => $this->person, 'session' => 'session-2']);

        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::SESSION_INELIGIBLE, $refused->reason);
        self::assertNull($refused->navigation);
        self::assertSame(['error' => FailureReason::SESSION_INELIGIBLE->value], $refused->body());
    }

    /**
     * An enabled OIDC connection of the tenant to another provider, whose
     * authorisation endpoint carries the query given.
     *
     * @param  string  $issuer
     * @param  string  $query
     * @return string
     */
    private function connectionAt(string $issuer, string $query): string
    {
        $provider = new FakeOpenIdProvider($issuer, clock: $this->clock);

        return $this->makeOidcConnection($provider, ['authorization_endpoint' => $provider->endpoint('authorization') . $query]);
    }

    /**
     * Deliver the provider's answer to the connection's callback, and read the
     * redirect the browser is sent back with.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization  $grant
     * @return \SineMacula\Laravel\Sso\Testing\HandoffRedirect
     */
    private function completeAt(FakeAuthorization $grant): HandoffRedirect
    {
        $result = app(CompletionService::class)->callback($this->connectionId, new CompletionRequest('GET', $grant->query(), []));

        return HandoffRedirect::from(app(CompletionResponses::class)->from($result, 'GET'));
    }

    /**
     * Admit the handoff in the application's transaction on the package's
     * storage connection, with the verifier the client kept.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Testing\HandoffRedirect  $redirect
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function admit(Purpose $purpose, HandoffRedirect $redirect): RedemptionResult
    {
        $code         = $redirect->code();
        $connectionId = $this->connectionId;

        return DB::connection(StorageConnection::name())->transaction(
            static fn (): RedemptionResult => app(HandoffRedemption::class)->admit($purpose, self::APPLICATION, $connectionId, $code, self::VERIFIER),
        );
    }

    /**
     * The sign-in start endpoint's answer to the connection and challenge the
     * client sends.
     *
     * @param  array{connection: string, code_challenge: ?string}  $input
     * @return \Illuminate\Http\JsonResponse
     */
    private static function startSigningIn(array $input): JsonResponse
    {
        $response = require __DIR__ . '/start/sign-in.php';

        self::assertInstanceOf(JsonResponse::class, $response);

        return $response;
    }

    /**
     * The reauthentication start for the caller the application authenticated,
     * with the client's challenge.
     *
     * @param  array{connection: string, code_challenge: ?string, identity: \SineMacula\Laravel\Sso\Identities\IdentityReference, session: string}  $input
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private static function startReauthenticating(array $input): StartResult
    {
        $result = require __DIR__ . '/start/reauthenticate.php';

        self::assertInstanceOf(StartResult::class, $result);

        return $result;
    }

    /**
     * The start response's body, once its status is the one expected and it is
     * never cached.
     *
     * @param  \Illuminate\Http\JsonResponse  $response
     * @param  int  $status
     * @return array<array-key, mixed>
     */
    private static function bodyOf(JsonResponse $response, int $status): array
    {
        self::assertSame($status, $response->getStatusCode());
        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));

        $body = $response->getData(true);

        self::assertIsArray($body);

        return $body;
    }

    /**
     * The URL a started body's `redirect` navigation sends the browser to.
     *
     * @param  array<array-key, mixed>  $body
     * @return string
     */
    private static function navigationUrl(array $body): string
    {
        $navigation = $body['navigation'] ?? null;

        self::assertIsArray($navigation);
        self::assertSame('redirect', $navigation['type'] ?? null);
        self::assertIsString($navigation['url'] ?? null);

        return $navigation['url'];
    }
}
