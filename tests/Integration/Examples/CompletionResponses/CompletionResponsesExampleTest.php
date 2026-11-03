<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\CompletionResponses;

use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Responses\CompletionResponse;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/completion-responses.md` (SSO-5.6, SSO-5.7,
 * SSO-12.1, SSO-12.5), on the shared example harness: the completion routes of
 * `routes/api.php` and the controller that returns what `CompletionResponses`
 * builds, run over HTTP for each protocol. Each asserts the status, the
 * `Location`, the headers and the body the guide's table gives: a `303` after
 * the posted SAML response and a `302` after the OIDC callback, each carrying
 * the code and the reference; and the refusals, a replayed response's `400`
 * with no redirect, a provider's error as a failure redirect naming its code,
 * and a full completion limit's `429` with its wait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionResponses::class)]
#[CoversClass(CompletionResponse::class)]
final class CompletionResponsesExampleTest extends ExampleTestCase
{
    /** @var string Where the routes are served from, with Laravel's API prefix. */
    private const string BASE_URL = 'https://sp.example.test/api';

    /** @var string The body of every redirect, in the default locale. */
    private const string REDIRECTING = 'Returning you to the application.';

    /** @var string The body of every refusal, in the default locale. */
    private const string INVALID = 'The sign-in response could not be accepted.';

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
     * The posted SAML response is answered with a `303` to the redirect URI,
     * the code and then the reference in its fragment, and the code links the
     * subject; the same response posted again is a `400` with no `Location` and
     * a body that says nothing of why.
     *
     * @return void
     */
    public function testTheAssertionConsumerServiceAnswersAPostWithA303(): void
    {
        $start  = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $posted = $this->postedResponse($start);
        $route  = '/api/auth/sso/connections/' . $this->connectionId . '/assertions';

        $completed = $this->post($route, $posted);
        $redirect  = self::redirectOf($completed, 303);

        self::assertSame(self::REDIRECT_URI . '#code=' . $redirect->code() . '&reference=' . $start->reference?->value, $completed->headers->get('Location'));
        $completed->assertContent(self::REDIRECTING);
        self::assertTrue($this->redeemLink($this->connectionId, $redirect, $start, $this->person)->isRedeemed());

        $replayed = $this->post($route, $posted);

        self::assertRefused($replayed, 400);
        self::assertFalse($replayed->headers->has('Retry-After'));
    }

    /**
     * The OIDC authorisation response is answered with a `302` carrying the
     * code and the reference; a provider's error is answered with a `302` to
     * the same redirect URI naming the failure reason's code, never the
     * provider's own error or its description.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheCallbackAnswersAGetWithA302(): void
    {
        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);
        $callback     = '/api/auth/sso/connections/' . $connectionId . '/callback?';

        $start     = $this->startFlow(Purpose::LINK, $connectionId, $this->person);
        $completed = $this->get($callback . $provider->authorize($start)->query());
        $redirect  = self::redirectOf($completed, 302);

        self::assertSame(self::REDIRECT_URI . '#code=' . $redirect->code() . '&reference=' . $start->reference?->value, $completed->headers->get('Location'));
        $completed->assertContent(self::REDIRECTING);

        $start  = $this->startFlow(Purpose::LINK, $connectionId, $this->person);
        $failed = $this->get($callback . $provider->authorize($start)->errorQuery('access_denied', 'The user said no'));
        $error  = self::redirectOf($failed, 302);

        self::assertFalse($error->hasCode());
        self::assertSame(self::REDIRECT_URI . '#error=provider_error&reference=' . $start->reference?->value, $failed->headers->get('Location'));
        self::assertSame(FailureReason::PROVIDER_ERROR->value, $error->error);
        $failed->assertContent(self::REDIRECTING);
    }

    /**
     * Once the connection's completion limit is full, the next response is
     * answered with a `429` and the seconds until the limit's window ends, and
     * with no redirect.
     *
     * @return void
     */
    public function testAFullCompletionLimitIsA429WithItsWait(): void
    {
        config()->set('sso.rate_limits.completion.per_connection', ['max' => 1, 'decay_seconds' => 60]);

        $start  = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $posted = $this->postedResponse($start);
        $route  = '/api/auth/sso/connections/' . $this->connectionId . '/assertions';

        self::redirectOf($this->post($route, $posted), 303);

        $limited = $this->post($route, $posted);

        self::assertRefused($limited, 429);
        self::assertSame('60', $limited->headers->get('Retry-After'));
    }

    /**
     * The fields the browser posts to the assertion consumer service: the
     * provider's signed response to the started flow, with its relay state.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return array<string, string>
     */
    private function postedResponse(StartResult $start): array
    {
        $request = $this->idp->receive($start);

        return $this->idp->respondTo($request, $this->clock->now())->post($request->relayState);
    }

    /**
     * The redirect a completion route answered with the status given, sent with
     * the headers every completion response carries.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  int  $status
     * @return \SineMacula\Laravel\Sso\Testing\HandoffRedirect
     */
    private static function redirectOf(TestResponse $response, int $status): HandoffRedirect
    {
        self::assertSentWithTheHeaders($response->assertStatus($status));

        return HandoffRedirect::from($response->headers->get('Location'));
    }

    /**
     * A refusal: the status given, no `Location`, the body that says nothing of
     * why, and the headers every completion response carries.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  int  $status
     * @return void
     */
    private static function assertRefused(TestResponse $response, int $status): void
    {
        self::assertSentWithTheHeaders($response->assertStatus($status)->assertHeaderMissing('Location'));
        $response->assertContent(self::INVALID);
    }

    /**
     * The response was sent with `Cache-Control: no-store` (which Symfony
     * writes as `no-store, private`), `Referrer-Policy: no-referrer` and a
     * plain text `Content-Type`.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @return void
     */
    private static function assertSentWithTheHeaders(TestResponse $response): void
    {
        $response->assertHeader('Cache-Control', 'no-store, private')
            ->assertHeader('Referrer-Policy', 'no-referrer')
            ->assertHeader('Content-Type', 'text/plain; charset=UTF-8');
    }
}
