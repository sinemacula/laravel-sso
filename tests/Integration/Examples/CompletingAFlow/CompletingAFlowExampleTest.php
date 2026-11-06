<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\CompletingAFlow;

use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/completing-a-flow.md` (SSO-5.6, SSO-12.5), on
 * the shared example harness: the completion service resolved for a request,
 * the completion routes of `routes/api.php` and their controller run over HTTP
 * for each protocol, and an application that allows unlinked handoffs. Each
 * asserts its outcome and a refusal: a replayed response, a response delivered
 * at another connection's route, and an unlinked sign-in where the application
 * does not allow unlinked handoffs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionResponses::class)]
#[CoversClass(CompletionResult::class)]
final class CompletingAFlowExampleTest extends ExampleTestCase
{
    /** @var string Where the routes are served from, with Laravel's API prefix. */
    private const string BASE_URL = 'https://sp.example.test/api';

    /** @var string The issuer of a second OpenID provider. */
    private const string OTHER_ISSUER = 'https://other-op.example.test';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The tenant's SAML identity provider. */
    private FakeSamlIdentityProvider $idp;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /**
     * Serve the completion routes under the API prefix the base URL carries,
     * and make the tenant's SAML connection and the person.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.endpoints.base_url', self::BASE_URL);
        Route::prefix('api')->group(__DIR__ . '/routes.php');

        $this->idp          = new FakeSamlIdentityProvider;
        $this->connectionId = $this->makeSamlConnection($this->idp);
        $this->person       = new IdentityReference('App\Models\User', 'person-1');
    }

    /**
     * The service resolved for a request completes the flow its response
     * answers; the service the next request resolves is another, and the same
     * response again names no request, so it is rejected as `request_unknown`.
     *
     * @return void
     */
    public function testTheServiceIsResolvedForEachRequest(): void
    {
        $start    = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $request  = $this->idp->receive($start);
        $response = $this->idp->respondTo($request, $this->clock->now());

        // @snippet-start completion-service
        $completions = app(CompletionService::class);
        // @snippet-end completion-service
        $result = $completions->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $this->connectionId,
            $response->completionRequest($request->relayState),
            Clients::browser(),
        );

        self::assertTrue($result->isCompleted());
        self::assertSame($start->reference?->value, $result->reference?->value);

        $next     = app(CompletionService::class);
        $replayed = $next->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connectionId, $response->completionRequest($request->relayState), Clients::browser());

        self::assertNotSame($completions, $next);
        self::assertTrue($replayed->isRejected());
        self::assertSame(FailureReason::REQUEST_UNKNOWN, $replayed->reason);
    }

    /**
     * The browser posts the SAML response to the assertion consumer service
     * route, which redirects it with a `303` carrying the code and the
     * request's reference, and the code links the subject; the same response
     * posted again is a `400` with no redirect.
     *
     * @return void
     */
    public function testTheAssertionConsumerServiceRouteCompletesASamlFlow(): void
    {
        $start    = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $request  = $this->idp->receive($start);
        $posted   = $this->idp->respondTo($request, $this->clock->now())->post($request->relayState);
        $route    = '/api/auth/sso/connections/' . $this->connectionId . '/assertions';
        $redirect = self::redirectOf($this->post($route, $posted), 303);

        self::assertSame($start->reference?->value, $redirect->reference);
        self::assertTrue($this->redeemLink($this->connectionId, $redirect, $start, $this->person)->isRedeemed());

        $this->post($route, $posted)->assertStatus(400)->assertHeaderMissing('Location');
    }

    /**
     * The provider sends the browser to the callback route, which redirects it
     * with a `302` carrying the code and the request's reference; the response
     * to a request of that connection, delivered at another connection's
     * callback, fails with `connection_mismatch` and no code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheCallbackRouteCompletesAnOidcFlow(): void
    {
        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);
        $otherId      = $this->makeOidcConnection(new FakeOpenIdProvider(self::OTHER_ISSUER, clock: $this->clock));

        $start    = $this->startFlow(Purpose::LINK, $connectionId, $this->person);
        $callback = '/api/auth/sso/connections/' . $connectionId . '/callback?' . $provider->authorize($start)->query();
        $redirect = self::redirectOf($this->get($callback), 302);

        self::assertTrue($redirect->hasCode());
        self::assertSame($start->reference?->value, $redirect->reference);

        $start    = $this->startFlow(Purpose::LINK, $connectionId, $this->person);
        $callback = '/api/auth/sso/connections/' . $otherId . '/callback?' . $provider->authorize($start)->query();
        $refused  = self::redirectOf($this->get($callback), 302);

        self::assertFalse($refused->hasCode());
        self::assertSame(FailureReason::CONNECTION_MISMATCH->value, $refused->error);
        self::assertSame($start->reference?->value, $refused->reference);
    }

    /**
     * A `sign_in` that resolves to no identity ends with `unlinked` by default;
     * once the application allows unlinked handoffs, the same sign-in is issued
     * a code that carries no linked identity, admitted with the verified
     * result, so the application decides who signed in and writes no session
     * here.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnApplicationMayAllowUnlinkedHandoffs(): void
    {
        $start   = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $refused = $this->respondAtProvider($this->idp, $this->connectionId, $start);

        self::assertFalse($refused->hasCode());
        self::assertSame(FailureReason::UNLINKED->value, $refused->error);

        /** @var array<string, mixed> $sso */
        $sso = config('sso');

        config()->set('sso', [
            ...$sso,
            // @snippet-start unlinked-handoffs
            'applications' => [
                'web' => [
                    'redirect_uri'      => 'https://app.example.com/sso',
                    'external_sign_in'  => true,
                    'unlinked_handoffs' => true,
                ],
            ],
            // @snippet-end unlinked-handoffs
        ]);

        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);
        $admitted = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

        self::assertTrue($admitted->isAdmitted());
        self::assertNull($admitted->linkedIdentity);
        self::assertSame(FakeSamlIdentityProvider::ENTITY_ID, $admitted->result?->issuer);
        self::assertNull($this->sessions->authenticatedAt('session-1'));
    }

    /**
     * The redirect a completion route answered with the status given.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  int  $status
     * @return \SineMacula\Laravel\Sso\Testing\HandoffRedirect
     */
    private static function redirectOf(TestResponse $response, int $status): HandoffRedirect
    {
        $response->assertStatus($status);

        return HandoffRedirect::from($response->headers->get('Location'));
    }
}
