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
 * The examples of `docs/guides/completion-responses.md`, run over HTTP for each
 * protocol.
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
     * Serve the completion routes under the API prefix, and make the SAML
     * connection and the person.
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
     * A posted SAML response gets a `303` with the code; a replay gets a bare
     * `400`.
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
     * The OIDC callback gets a `302` with the code, and a provider's error only
     * as a failure reason's code.
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
     * A full completion limit answers `429` with its wait and no redirect.
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
     * The fields the browser posts to the assertion consumer service.
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
     * Assert a redirect with the status given and the shared headers.
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
     * Assert a refusal: the status given, no `Location`, the generic body and
     * the shared headers.
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
     * Assert the headers every completion response carries; Symfony writes
     * `no-store` as `no-store, private`.
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
