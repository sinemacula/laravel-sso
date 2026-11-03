<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OidcCallback;

use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/oidc-callback.md` (SSO-5.6, SSO-7.1, SSO-7.2,
 * SSO-12.5), on the shared example harness: the callback route and its
 * controller run over HTTP, and a connection changed to authenticate at the
 * token endpoint with `client_secret_post`. Each asserts its outcome and a
 * refusal: the callback answers the provider's response with a `302` carrying a
 * code that links the person, and a query that repeats a parameter with a `400`
 * and no redirect, consuming nothing; the changed connection completes a flow
 * through a token endpoint that accepts only `client_secret_post` with the new
 * secret, while the flow already in flight when the secret changed is refused
 * `connection_unavailable`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionResponses::class)]
#[CoversClass(ConnectionService::class)]
final class OidcCallbackExampleTest extends ExampleTestCase
{
    /** @var string The client id the provider registers the connection under. */
    private const string CLIENT_ID = 'the-client-id';

    /** @var string The secret the provider issues for it. */
    private const string SECRET = 'a-rotated-client-secret';

    /** @var string The body of every refusal, in the default locale. */
    private const string INVALID = 'The sign-in response could not be accepted.';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /**
     * Serve the callback route, and make the tenant's OIDC connection and the
     * person.
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
        $this->person       = new IdentityReference('App\Models\User', 'person-1');
    }

    /**
     * The flow names the route's URL as its `redirect_uri`, and the provider's
     * response delivered there is answered with a `302` to the application's
     * redirect URI, carrying a code and the request's reference; the code links
     * the person.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheCallbackRouteCompletesTheFlow(): void
    {
        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $grant = $this->provider->authorize($start);

        self::assertSame('https://sp.example.test' . $this->callbackPath(), $grant->parameter('redirect_uri'));

        $redirect = self::redirectOf($this->get($this->callbackPath() . '?' . $grant->query()));

        self::assertTrue($redirect->hasCode());
        self::assertSame($start->reference?->value, $redirect->reference);
        self::assertTrue($this->redeemLink($this->connectionId, $redirect, $start, $this->person)->isRedeemed());
    }

    /**
     * A query that repeats `state`, even with the same value, is answered with
     * a `400`, no `Location` and a body that says nothing of why, before any
     * request is looked up; so the request is not consumed, and the provider's
     * response delivered whole afterwards still completes it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARepeatedParameterIsRefusedBeforeAnythingIsRead(): void
    {
        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $grant = $this->provider->authorize($start);
        $query = $grant->query();

        $refused = $this->get($this->callbackPath() . '?' . $query . '&state=' . $grant->parameter('state'));

        $refused->assertStatus(400)->assertHeaderMissing('Location');
        $refused->assertContent(self::INVALID);

        $redirect = self::redirectOf($this->get($this->callbackPath() . '?' . $query));

        self::assertTrue($redirect->hasCode());
        self::assertSame($start->reference?->value, $redirect->reference);
    }

    /**
     * Once the connection authenticates with `client_secret_post` and the new
     * secret, a flow completes through a token endpoint that accepts nothing
     * else, its one token request carrying that client id and secret in the
     * form; the flow started before the change is refused
     * `connection_unavailable`, since rotating the secret voided it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAConnectionAuthenticatesWithClientSecretPost(): void
    {
        $inFlight = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);

        $this->provider->register(self::CLIENT_ID, 'client_secret_post', self::SECRET);

        $connections  = app(ConnectionService::class);
        $tenantId     = self::TENANT;
        $connectionId = $this->connectionId;
        $secret       = self::SECRET;

        // @snippet-start oidc-client-secret-post
        $connections->update($tenantId, $connectionId, ['settings' => [
            'client_id'             => 'the-client-id',
            'client_authentication' => 'client_secret_post',
            'client_secret'         => $secret,
        ]]);
        // @snippet-end oidc-client-secret-post
        $changed = $connections->get($tenantId, $connectionId);

        self::assertNotNull($changed);
        self::assertSame(self::CLIENT_ID, $changed->settings['client_id'] ?? null);
        self::assertSame('client_secret_post', $changed->settings['client_authentication'] ?? null);
        self::assertTrue($changed->usable);

        $voided = self::redirectOf($this->get($this->callbackPath() . '?' . $this->provider->authorize($inFlight)->query()));

        self::assertFalse($voided->hasCode());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE->value, $voided->error);
        self::assertSame($inFlight->reference?->value, $voided->reference);

        $start    = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $redirect = self::redirectOf($this->get($this->callbackPath() . '?' . $this->provider->authorize($start)->query()));

        self::assertTrue($this->redeemLink($this->connectionId, $redirect, $start, $this->person)->isRedeemed());
        $this->assertOneTokenRequestPostedTheSecret();
    }

    /**
     * The path of the connection's callback, as the route serves it.
     *
     * @return string
     */
    private function callbackPath(): string
    {
        return '/auth/sso/connections/' . $this->connectionId . '/callback';
    }

    /**
     * Exactly one token request was made, and it authenticated with
     * `client_secret_post`, the provider's client id and the new secret.
     *
     * @return void
     */
    private function assertOneTokenRequestPostedTheSecret(): void
    {
        $tokens = array_values(array_filter($this->fetcher->requests(), static fn (FetchRequest $request): bool => $request->purpose === FetchPurpose::TOKEN));

        self::assertCount(1, $tokens);

        $credentials = $tokens[0]->credentials;

        self::assertNotNull($credentials);
        self::assertSame(CredentialKind::CLIENT_SECRET_POST, $credentials->kind);
        self::assertSame(self::CLIENT_ID, $credentials->clientId);
        self::assertSame(self::SECRET, $credentials->secret());
    }

    /**
     * The redirect the callback answered with: a `302` whose `Location` is the
     * application's redirect URI.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @return \SineMacula\Laravel\Sso\Testing\HandoffRedirect
     */
    private static function redirectOf(TestResponse $response): HandoffRedirect
    {
        $response->assertStatus(302);

        self::assertStringStartsWith(self::REDIRECT_URI . '#', (string) $response->headers->get('Location'));

        return HandoffRedirect::from($response->headers->get('Location'));
    }
}
