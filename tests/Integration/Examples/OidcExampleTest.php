<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;

/**
 * The testing guide's OpenID Connect examples: each purpose from start to
 * redemption, the provider's clock, and its keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeOpenIdProvider::class)]
#[CoversClass(HandoffRedirect::class)]
final class OidcExampleTest extends ExampleTestCase
{
    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /**
     * Make the provider on the package's clock, a connection to it, and the
     * person.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        // @snippet-start oidc-provider
        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);
        // @snippet-end oidc-provider
        $this->person = new IdentityReference('App\Models\User', 'person-1');
    }

    /**
     * A `link` links only for the identity it was started for.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testLinkingASubjectToAnIdentity(): void
    {
        // @snippet-start oidc-link-refused
        $start    = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);
        $refused  = $this->redeemLink($this->connectionId, $redirect, $start, new IdentityReference('App\Models\User', 'someone-else'));

        self::assertSame(FailureReason::IDENTITY_MISMATCH, $refused->reason);
        // @snippet-end oidc-link-refused
        $client = Clients::browser();
        // @snippet-start oidc-link
        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);

        // The provider grants the authorisation request the start sent, as its
        // authorisation endpoint would
        $grant = $this->provider->authorize($start);

        // The browser arrives at the callback with the grant's query
        $result   = app(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $this->connectionId, new CompletionRequest('GET', $grant->query(), []), $client);
        $redirect = HandoffRedirect::from(app(CompletionResponses::class)->from($result, 'GET'));

        self::assertSame($start->reference?->value, $redirect->reference);

        $linked = $this->redeemLink($this->connectionId, $redirect, $start, $this->person);

        self::assertTrue($linked->isRedeemed());
        self::assertNotNull($linked->linkId);
        // @snippet-end oidc-link
    }

    /**
     * A `sign_in` admits the linked person; a token signed by an unpublished
     * key fails the flow.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testSigningIn(): void
    {
        $this->linkThroughFlow($this->provider, $this->connectionId, $this->person);

        // @snippet-start oidc-sign-in
        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);
        $signedIn = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

        self::assertTrue($signedIn->isAdmitted());
        self::assertEquals($this->person, $signedIn->linkedIdentity);
        // @snippet-end oidc-sign-in
        // @snippet-start oidc-sign-in-refused
        // Another key, under the kid the provider published
        $forger   = FakeSigningKey::rsa('rsa-1');
        $forged   = static fn (FakeIdToken $token): FakeIdToken => $token->signedWith($forger, 'RS256');
        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start, $forged);

        self::assertSame(FailureReason::SIGNATURE_INVALID->value, $redirect->error);
        // @snippet-end oidc-sign-in-refused
    }

    /**
     * A `reauthenticate` code is refused at sign-in and renews the session when
     * admitted for its purpose.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testReauthenticating(): void
    {
        $this->linkThroughFlow($this->provider, $this->connectionId, $this->person);
        $this->signInThroughFlow($this->provider, $this->connectionId, 'session-1');

        $this->clock->advance(3600);

        // @snippet-start oidc-reauthenticate-refused
        $start    = $this->startFlow(Purpose::REAUTHENTICATE, $this->connectionId, $this->person, 'session-1');
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);
        $refused  = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-2');

        self::assertSame(FailureReason::PURPOSE_MISMATCH, $refused->reason);
        // @snippet-end oidc-reauthenticate-refused
        $client = Clients::browser();
        // @snippet-start oidc-reauthenticate
        $start = $this->startFlow(Purpose::REAUTHENTICATE, $this->connectionId, $this->person, 'session-1');
        $grant = $this->provider->authorize($start);

        self::assertSame(['login', '0'], [$grant->parameter('prompt'), $grant->parameter('max_age')]);

        $result   = app(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $this->connectionId, new CompletionRequest('GET', $grant->query(), []), $client);
        $redirect = HandoffRedirect::from(app(CompletionResponses::class)->from($result, 'GET'));
        $renewed  = $this->admitReauthentication($this->connectionId, $redirect, $start);

        self::assertTrue($renewed->isAdmitted());
        self::assertSame('2026-11-01T10:30:00Z', $this->sessions->authenticatedAt('session-1')?->toIso8601ZuluString());
        // @snippet-end oidc-reauthenticate
    }

    /**
     * The provider issues tokens at the package's now, whatever Laravel's time
     * travel does.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheProviderReadsThePackagesClock(): void
    {
        // @snippet-start oidc-clock
        $this->travelTo(CarbonImmutable::parse('2026-11-02T09:30:00Z'));

        $this->linkThroughFlow($this->provider, $this->connectionId, $this->person);

        $signedIn = $this->signInThroughFlow($this->provider, $this->connectionId, 'session-1');

        self::assertTrue($signedIn->isAdmitted());
        // @snippet-end oidc-clock
        $this->travelBack();
    }

    /**
     * The JWKS is fetched when a token first names a key, and refetched at most
     * once a cooldown.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testKeysAreFetchedWhenATokenNamesThem(): void
    {
        // @snippet-start oidc-jwks
        $this->linkThroughFlow($this->provider, $this->connectionId, $this->person);

        $this->fetcher->assertFetched($this->provider->endpoint('jwks'), FetchPurpose::JWKS);
        self::assertSame(1, $this->jwksFetches());

        // The provider rotates to a new key, and the cooldown passes
        $next = FakeSigningKey::rsa('rsa-2');

        $this->provider->publish($next)->signWith($next);
        $this->clock->advance(301);

        self::assertTrue($this->signInThroughFlow($this->provider, $this->connectionId, 'session-1')->isAdmitted());
        self::assertSame(2, $this->jwksFetches());
        // @snippet-end oidc-jwks
        // @snippet-start oidc-jwks-refused
        $unknown  = FakeSigningKey::rsa('rsa-3');
        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start, static fn (FakeIdToken $token): FakeIdToken => $token->signedWith($unknown, 'RS256'));

        self::assertSame(FailureReason::SIGNATURE_INVALID->value, $redirect->error);
        self::assertSame(2, $this->jwksFetches());
        // @snippet-end oidc-jwks-refused
    }

    /**
     * How many times the provider's JWKS has been fetched.
     *
     * @return int
     */
    private function jwksFetches(): int
    {
        $jwks = $this->provider->endpoint('jwks');

        return count(array_filter($this->fetcher->requests(), static fn (FetchRequest $request): bool => $request->url === $jwks));
    }
}
