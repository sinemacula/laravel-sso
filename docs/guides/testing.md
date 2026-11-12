# Testing Your SSO Flows

The package ships what your application needs to test its SSO flows without a network, under
`SineMacula\Laravel\Sso\Testing`: a fake SAML identity provider and a fake OpenID provider (keys, signed responses and
ID tokens, metadata, a JWKS, token and UserInfo endpoints), a fake DNS resolver, a fake fetcher, a frozen clock, a fake
freshness contract, and a reader for the redirect your client receives.

Every example in this guide is a test that runs with the package's own suite, in `tests/Integration/Examples`, and each
snippet below is taken from it: a test fails when a snippet and its source differ (see
[Keeping the examples honest](#keeping-the-examples-honest)). The examples use the package's public API and nothing
else, as your tests would: no test trait or fixture of the package's, no read of its tables, and no verified result
built by hand. A SAML flow is correlated from the `AuthnRequest` the start really sent, never from a request id the test
guessed.

## The helpers

| Helper                                        | Stands in for                                    | What to know                                                                                                                                                     |
|-----------------------------------------------|--------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `FakeSamlIdentityProvider`                    | A SAML identity provider                         | Its own key and certificate; `receive()` reads the `AuthnRequest` a start sent and `respondTo()` answers it; `response()` makes an unsolicited one; `metadata()` |
| `Saml\FakeAuthnRequest`                       | What the provider's single sign-on service reads | The request's `ID`, `Issuer`, assertion consumer service, `Destination`, `ForceAuthn` and `RelayState`, from either binding                                      |
| `Saml\FakeSamlResponse`                       | A SAML `Response`                                | Valid by default; `with()` changes any part, and `signedBy()`, `encryptedFor()` and `wrapped()` make the hostile ones                                            |
| `Saml\FakeSamlMetadata`                       | The provider's metadata                          | Unsigned unless asked; `with()` and `signedBy()`                                                                                                                 |
| `Saml\FakeServiceProvider`                    | How the provider is told of your service         | The entity id and assertion consumer service, read from your connection's service provider metadata                                                              |
| `Saml\XmlSigner`                              | The provider's signing                           | The enveloped signature of responses and metadata, every algorithm and key a hostile case needs                                                                  |
| `Saml\AssertionEncryptor`                     | The provider's encryption                        | An `EncryptedAssertion` for your service provider's certificate                                                                                                  |
| `Saml\SignatureWrapping`                      | An attacker                                      | The XSW1 to XSW8 wrapping attacks on a signed response                                                                                                           |
| `Saml\ResponseWriter`                         | The provider's XML                               | Writes a response from its options; `FakeSamlResponse` uses it                                                                                                   |
| `FakeOpenIdProvider`                          | An OpenID provider                               | Discovery, JWKS, token and UserInfo endpoints on the fake fetcher; `authorize()` grants the request a start sent                                                 |
| `Oidc\FakeAuthorization`                      | The provider's grant                             | The code, the ID token and access token it is exchanged for, and the callback's `query()`                                                                        |
| `Oidc\FakeIdToken`                            | An ID token                                      | Valid by default; `with()`, `without()`, `signedWith()` and the hostile forms                                                                                    |
| `Oidc\FakeSigningKey`                         | The provider's keys                              | RSA or elliptic curve, with a `kid`, published or kept back                                                                                                      |
| `Oidc\FakeTokenEndpoint`                      | The token endpoint                               | Exchanges a code once, for the client and the verifier it was granted to                                                                                         |
| `Oidc\HostileIdTokens`, `Oidc\HostileIdToken` | An attacker                                      | Every hostile ID token of the adversarial suite, each with the reason a completion ends with                                                                     |
| `Oidc\JwsSigner`, `Oidc\PssSignature`         | The provider's signing                           | Signs tokens with OpenSSL alone, never with the package's JOSE library                                                                                           |
| `FakeFetcher`                                 | Every outbound request                           | Answers each URL with what you give it; throws for any other                                                                                                     |
| `FakeDnsResolver`                             | DNS                                              | Answers each TXT lookup with what you give it; throws for any other                                                                                              |
| `FrozenClock`                                 | The package's clock                              | Holds one instant until the test moves it                                                                                                                        |
| `FakeFreshness`                               | Your freshness contract                          | Answers `fresh` or `stale` as the test says, and records what it was asked                                                                                       |
| `HandoffRedirect`                             | Your client                                      | Reads the code, the reference or the failure from the redirect a completion answers                                                                              |

## A test case

Bind the fakes in place of the package's seams, and your own contracts for the flows you test: below, sessions an
in-memory `ReauthenticationSessions` keeps, a `LinkEligibility` that lets everyone link, and the package's link store as
the linker. Configure the protocols, your service's base URL and your application.

<!-- snippet: tests/Integration/Examples/ExampleTestCase.php#test-case -->

```php
$this->clock     = new FrozenClock('2026-11-01T09:30:00Z');
$this->fetcher   = new FakeFetcher;
$this->dns       = new FakeDnsResolver;
$this->freshness = FakeFreshness::fresh();
$this->sessions  = new ExampleSessions;

$this->instance(Clock::class, $this->clock);
$this->instance(Fetcher::class, $this->fetcher);
$this->instance(DnsResolver::class, $this->dns);
$this->instance(Freshness::class, $this->freshness);
$this->instance(ReauthenticationSessions::class, $this->sessions);
$this->instance(LinkEligibility::class, new EveryoneMayLink);
$this->instance(Linker::class, app(LinkStore::class));

config()->set('sso.features.saml2', true);
config()->set('sso.features.oidc', true);
config()->set('sso.endpoints.base_url', 'https://sp.example.test');
config()->set('sso.applications', [
    'web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
]);
```

Run the package's migrations as your application already runs its own, but never wrap a test in a transaction on the
package's storage connection: the start, completion and import helpers refuse to run inside one, and a redemption that
writes a session must open its own. Use `DatabaseMigrations` or `DatabaseTruncation`, not `RefreshDatabase`.

The examples keep their sessions in `Tests\Integration\Examples\Application\ExampleSessions`, their eligibility in
`EveryoneMayLink`, the people linking by a verified domain asks about in `ExampleDirectory`, and their provisioning in
`ProvisionNewPeople`, all beside the examples. Your own contracts read your tables, and lock as the guides for each say;
an in-memory one is enough for a test of the package's flows, never for production.

### Connections

Create each connection through the management helpers, as an administrator would: the provider's settings, and its
certificate trusted for SAML. The test case then enables it with `ConnectionService::enable()` and checks that
`ConnectionService::get()` says it is usable. The fake freshness contract lets each of these changes through.

<!-- snippet: tests/Integration/Examples/ExampleTestCase.php#saml-connection -->

```php
$created = app(ConnectionService::class)->create(self::TENANT, 'saml2', 'Example SAML', $client, [
    'idp_entity_id' => $idp->entityId,
    'sso_url'       => FakeSamlIdentityProvider::SSO_URL,
    ...$settings,
]);

$connectionId = (string) $created->connection?->id;

static::assertTrue(app(KeyService::class)->trustCertificate(self::TENANT, $connectionId, $idp->certificate(), $client)->isSucceeded());
```

`$client` is the `Http\ClientContext` the test acts for, as a controller builds it from its request:
`new ClientContext('203.0.113.7', 'Example/1.0')`, say, or `new ClientContext(null, null)` for work with no client.
Every call that counts an attempt or reports an event takes one, and each event carries its IP address and user agent.

<!-- snippet: tests/Integration/Examples/ExampleTestCase.php#oidc-connection -->

```php
$provider->serve($this->fetcher);

$created = app(ConnectionService::class)->create(self::TENANT, 'oidc', 'Example OIDC', $client, [
    'issuer'                 => $provider->issuer,
    'authorization_endpoint' => $provider->endpoint('authorization'),
    'token_endpoint'         => $provider->endpoint('token'),
    'jwks_uri'               => $provider->endpoint('jwks'),
    'client_id'              => FakeOpenIdProvider::CLIENT_ID,
    'client_secret'          => FakeOpenIdProvider::CLIENT_SECRET,
    ...$settings,
]);
```

An OIDC connection needs no keys stored: the first ID token names a key the connection does not hold, and the package
fetches the provider's JWKS then (see [OIDC keys](#oidc-keys)). Give the fake OpenID provider the clock the package
reads:

<!-- snippet: tests/Integration/Examples/OidcExampleTest.php#oidc-provider -->

```php
$this->provider     = new FakeOpenIdProvider(clock: $this->clock);
$this->connectionId = $this->makeOidcConnection($this->provider);
```

### The client's side

A test plays your client: it starts a flow, sends the browser to the provider, reads the redirect the completion
answers, checks the reference is the one it started, and redeems the code with its verifier. A `link` is redeemed alone,
as the caller your application has authenticated, an `Identities\Caller` of the identity and the session it is on:

<!-- snippet: tests/Integration/Examples/ExampleTestCase.php#redeem-link -->

```php
return app(HandoffRedemption::class)->redeem(Purpose::LINK, self::APPLICATION, $connectionId, $redirect->code(), self::verifierOf($start), $client, $caller);
```

A `sign_in` is admitted inside your transaction on the package's storage connection, and the session is written in that
same transaction (see [Redeeming a handoff](redeeming-a-handoff.md)):

<!-- snippet: tests/Integration/Examples/ExampleTestCase.php#admit-sign-in -->

```php
return DB::connection(StorageConnection::name())->transaction(function () use ($connectionId, $redirect, $start, $sessionId, $client): RedemptionResult {

    $result = app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, self::APPLICATION, $connectionId, $redirect->code(), self::verifierOf($start), $client);

    if ($result->isRedeemed() && $result->linkedIdentity !== null) {
        // As fresh as the provider says, or now when it said nothing
        $authenticatedAt = $result->result?->authenticationContext->authenticatedAt ?? $this->clock->now();

        $this->sessions->establish($sessionId, $result->linkedIdentity, self::APPLICATION, $connectionId, (string) $result->linkId, $authenticatedAt);
    }

    return $result;
});
```

A `reauthenticate` is admitted the same way, and the package renews the session through your
`ReauthenticationSessions` inside it.

## SAML

### Linking

The fake provider reads the `AuthnRequest` your start sent, from the HTTP-Redirect URL or the HTTP-POST form, and
answers it: the response names the request's `ID` as its `InResponseTo`, and is made for its issuer and assertion
consumer service. The browser posts it back with the request's `RelayState`.

<!-- snippet: tests/Integration/Examples/SamlExampleTest.php#saml-link -->

```php
$start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);

// The provider reads the AuthnRequest the start sent, and answers it
$request  = $this->idp->receive($start);
$response = $this->idp->respondTo($request, $this->clock->now());

self::assertSame(FakeSamlIdentityProvider::SSO_URL, $request->destination);

// The browser posts the response, with the RelayState, to the assertion
// consumer service
$result = app(CompletionService::class)->complete(
    CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
    $this->connectionId,
    $response->completionRequest($request->relayState),
    $client,
);
$redirect = HandoffRedirect::from(app(CompletionResponses::class)->from($result, 'POST'));

// The client redeems only a code whose reference is the one it started
self::assertSame($start->reference?->value, $redirect->reference);

$linked = $this->redeemLink($this->connectionId, $redirect, $start, $this->person);

self::assertTrue($linked->isRedeemed());
self::assertNotNull($linked->linkId);
self::assertEquals($this->person, $linked->identity);
```

A code is redeemed once. The same code again is a replay:

<!-- snippet: tests/Integration/Examples/SamlExampleTest.php#saml-link-replayed -->

```php
$replayed = $this->redeemLink($this->connectionId, $redirect, $start, $this->person);

self::assertTrue($replayed->isRefused());
self::assertSame(FailureReason::REPLAYED, $replayed->reason);
```

### Signing in

With the subject linked, a sign-in resolves to the person. `respondAtProvider()` in the examples' test case runs the
same steps as the link above, for either protocol.

<!-- snippet: tests/Integration/Examples/SamlExampleTest.php#saml-sign-in -->

```php
$start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
$redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);
$signedIn = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

self::assertTrue($signedIn->isAdmitted());
self::assertEquals($this->person, $signedIn->linkedIdentity);
// The provider authenticated the person a minute before it answered
self::assertSame('2026-11-01T09:29:00Z', $this->sessions->authenticatedAt('session-1')?->toIso8601ZuluString());
```

A response signed by anyone the connection does not trust fails the flow, and the client is sent back with the failure
code and no handoff code:

<!-- snippet: tests/Integration/Examples/SamlExampleTest.php#saml-sign-in-refused -->

```php
$attacker = new FakeSamlIdentityProvider($this->idp->entityId);
$forged   = static fn (FakeSamlResponse $response): FakeSamlResponse => $response->signedBy($attacker->signer());
$start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
$redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start, $forged);

self::assertFalse($redirect->hasCode());
self::assertSame(FailureReason::SIGNATURE_INVALID->value, $redirect->error);
```

### Re-authenticating

A `reauthenticate` forces authentication at the provider (`ForceAuthn="true"`); the fake provider answers such a
request with an authentication made at the instant you give it, and the package renews the session to it:

<!-- snippet: tests/Integration/Examples/SamlExampleTest.php#saml-reauthenticate -->

```php
$this->clock->advance(3600);

$start   = $this->startFlow(Purpose::REAUTHENTICATE, $this->connectionId, $this->person, 'session-1');
$request = $this->idp->receive($start);

self::assertTrue($request->forceAuthn);

$redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);
$renewed  = $this->admitReauthentication($this->connectionId, $redirect, $start);

self::assertTrue($renewed->isAdmitted());
self::assertSame('session-1', $renewed->sessionId);
self::assertSame('2026-11-01T10:30:00Z', $this->sessions->authenticatedAt('session-1')?->toIso8601ZuluString());
```

A session the identity is not signed in on never starts a `reauthenticate`:

<!-- snippet: tests/Integration/Examples/SamlExampleTest.php#saml-reauthenticate-refused -->

```php
$refused = $this->startFlow(Purpose::REAUTHENTICATE, $this->connectionId, $this->person, 'session-2');

self::assertTrue($refused->isRefused());
self::assertSame(FailureReason::SESSION_INELIGIBLE, $refused->reason);
```

### IdP-initiated sign-in

An unsolicited response answers no request, so the fake provider is told of your service the way a real one is: from
the service provider metadata the connection describes. Turn the feature on and allow it on the connection:

<!-- snippet: tests/Integration/Examples/IdpInitiatedExampleTest.php#idp-initiated-connection -->

```php
config()->set('sso.features.idp_initiated', true);

$this->idp          = new FakeSamlIdentityProvider;
$this->connectionId = $this->makeSamlConnection($this->idp, [
    'idp_initiated'           => true,
    'idp_initiated_start_url' => 'https://app.example.com/sso/start',
]);
```

The response signs nobody in. It is re-initiated to your start URL, naming the connection, and the sign-in your start
route then begins is an ordinary SP-initiated one (see [IdP-initiated sign-in](idp-initiated-sign-in.md)):

<!-- snippet: tests/Integration/Examples/IdpInitiatedExampleTest.php#idp-initiated -->

```php
$metadata    = app(ServiceProviderDescriptions::class)->describe(self::TENANT, $this->connectionId);
$sp          = FakeServiceProvider::fromMetadata((string) $metadata->body);
$unsolicited = $this->idp->response($sp->entityId, $sp->assertionConsumerService, $this->clock->now());

$result   = app(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connectionId, $unsolicited->completionRequest(), $client);
$location = app(CompletionResponses::class)->from($result, 'POST')->location();

self::assertTrue($result->isReinitiated());
self::assertSame('https://app.example.com/sso/start?connection=' . $this->connectionId, $location);

// The start route reads the connection, and starts an ordinary sign-in
// through it
parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

$connectionId = $query['connection'] ?? null;

self::assertIsString($connectionId);

$start    = $this->startFlow(Purpose::SIGN_IN, $connectionId);
$redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);
$signedIn = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

self::assertEquals($person, $signedIn->linkedIdentity);
```

The response is recorded once it is re-initiated, so the same response posted again is rejected, with no redirect:

<!-- snippet: tests/Integration/Examples/IdpInitiatedExampleTest.php#idp-initiated-replayed -->

```php
$completions = app(CompletionService::class);

self::assertTrue($completions->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connectionId, $unsolicited->completionRequest(), $client)->isReinitiated());

$replayed = $completions->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connectionId, $unsolicited->completionRequest(), $client);

self::assertTrue($replayed->isRejected());
self::assertSame(FailureReason::REPLAYED, $replayed->reason);
self::assertNull(app(CompletionResponses::class)->from($replayed, 'POST')->location());
```

## OpenID Connect

### Linking

The fake provider grants the authorisation request your start sent, as its authorisation endpoint would: the code's ID
token carries the request's nonce and an `at_hash` of its access token, and the grant's `query()` is what the browser
brings back to the callback, with the RFC 9207 `iss`. Its token endpoint, on the fake fetcher, exchanges the code once,
for the client and the PKCE verifier the request named.

<!-- snippet: tests/Integration/Examples/OidcExampleTest.php#oidc-link -->

```php
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
```

Holding a code and its verifier proves which client started the flow, not who is calling now. A `link` redeemed by
anyone but the identity it was started for is refused, and the code is spent:

<!-- snippet: tests/Integration/Examples/OidcExampleTest.php#oidc-link-refused -->

```php
$start    = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
$redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);
$refused  = $this->redeemLink($this->connectionId, $redirect, $start, new IdentityReference('App\Models\User', 'someone-else'));

self::assertSame(FailureReason::IDENTITY_MISMATCH, $refused->reason);
```

### Signing in

<!-- snippet: tests/Integration/Examples/OidcExampleTest.php#oidc-sign-in -->

```php
$start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
$redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);
$signedIn = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

self::assertTrue($signedIn->isAdmitted());
self::assertEquals($this->person, $signedIn->linkedIdentity);
```

A tailor changes the ID token the provider issues. One signed by a key the provider never published, under a `kid` it
did, is refused:

<!-- snippet: tests/Integration/Examples/OidcExampleTest.php#oidc-sign-in-refused -->

```php
// Another key, under the kid the provider published
$forger   = FakeSigningKey::rsa('rsa-1');
$forged   = static fn (FakeIdToken $token): FakeIdToken => $token->signedWith($forger, 'RS256');
$start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
$redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start, $forged);

self::assertSame(FailureReason::SIGNATURE_INVALID->value, $redirect->error);
```

### Re-authenticating

A `reauthenticate` asks the provider for `prompt=login` and `max_age=0`; the fake provider authenticates the person at
the clock's now, and the package renews the session to it:

<!-- snippet: tests/Integration/Examples/OidcExampleTest.php#oidc-reauthenticate -->

```php
$start = $this->startFlow(Purpose::REAUTHENTICATE, $this->connectionId, $this->person, 'session-1');
$grant = $this->provider->authorize($start);

self::assertSame(['login', '0'], [$grant->parameter('prompt'), $grant->parameter('max_age')]);

$result   = app(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $this->connectionId, new CompletionRequest('GET', $grant->query(), []), $client);
$redirect = HandoffRedirect::from(app(CompletionResponses::class)->from($result, 'GET'));
$renewed  = $this->admitReauthentication($this->connectionId, $redirect, $start);

self::assertTrue($renewed->isAdmitted());
self::assertSame('2026-11-01T10:30:00Z', $this->sessions->authenticatedAt('session-1')?->toIso8601ZuluString());
```

The purpose is your endpoint's, never the code's: a `reauthenticate` code presented at your sign-in endpoint is refused,
and spent.

<!-- snippet: tests/Integration/Examples/OidcExampleTest.php#oidc-reauthenticate-refused -->

```php
$start    = $this->startFlow(Purpose::REAUTHENTICATE, $this->connectionId, $this->person, 'session-1');
$redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);
$refused  = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-2');

self::assertSame(FailureReason::PURPOSE_MISMATCH, $refused->reason);
```

### OIDC keys

The connection fetches the provider's JWKS when a token first names a key it does not hold, and again only once
`sso.oidc.jwks_refetch_cooldown_seconds` (300 by default) has passed, by the package's clock. A key the provider rotates
to is found on its first token after the cooldown:

<!-- snippet: tests/Integration/Examples/OidcExampleTest.php#oidc-jwks -->

```php
$this->linkThroughFlow($this->provider, $this->connectionId, $this->person);

$this->fetcher->assertFetched($this->provider->endpoint('jwks'), FetchPurpose::JWKS);
self::assertSame(1, $this->jwksFetches());

// The provider rotates to a new key, and the cooldown passes
$next = FakeSigningKey::rsa('rsa-2');

$this->provider->publish($next)->signWith($next);
$this->clock->advance(301);

self::assertTrue($this->signInThroughFlow($this->provider, $this->connectionId, 'session-1')->isAdmitted());
self::assertSame(2, $this->jwksFetches());
```

Within the cooldown, a token naming a key nobody published fetches nothing and is refused, so a flood of such tokens
cannot turn your servers on the provider:

<!-- snippet: tests/Integration/Examples/OidcExampleTest.php#oidc-jwks-refused -->

```php
$unknown  = FakeSigningKey::rsa('rsa-3');
$start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
$redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start, static fn (FakeIdToken $token): FakeIdToken => $token->signedWith($unknown, 'RS256'));

self::assertSame(FailureReason::SIGNATURE_INVALID->value, $redirect->error);
self::assertSame(2, $this->jwksFetches());
```

## Domains and linking by a verified domain

The fake DNS resolver answers a claimed domain's record name with its token once you tell it the tenant has published
it (`publishes()`), with no record (`absent()`), or with a failed lookup (`failing()`):

<!-- snippet: tests/Integration/Examples/DomainLinkingExampleTest.php#domain-verify -->

```php
$domains = app(DomainService::class);
$claimed = $domains->claim(self::TENANT, $this->connectionId, 'example.com', $client)->domain;

self::assertNotNull($claimed);
self::assertSame('_sso-verification.example.com', $claimed->recordName);

// The tenant has not published the record yet
$this->dns->absent($claimed->recordName);

self::assertSame(FailureReason::DOMAIN_RECORD_NOT_FOUND, $domains->verify(self::TENANT, $this->connectionId, 'example.com', $client)->reason);

// Now it has
$this->dns->publishes($claimed);

self::assertSame(DomainStatus::VERIFIED, $domains->verify(self::TENANT, $this->connectionId, 'example.com', $client)->status);

$this->dns->assertLookedUp($claimed->recordName, 2);
```

Linking by a verified domain asks three contracts of your application, each refusing by default: whose verified email
an address is, whether a person's principals sit within the tenant, and since when they have been its member. The
examples answer all three from one in-memory directory. Then turn the feature on, and linking on for the connection:

<!-- snippet: tests/Integration/Examples/DomainLinkingExampleTest.php#domain-linking-contracts -->

```php
config()->set('sso.features.domain_linking', true);

$this->directory = new ExampleDirectory;

$this->instance(LinkEmailMatcher::class, $this->directory);
$this->instance(PrincipalScope::class, $this->directory);
$this->instance(TenantMembership::class, $this->directory);
```

<!-- snippet: tests/Integration/Examples/DomainLinkingExampleTest.php#domain-linking-policy -->

```php
$changed = app(LinkingPolicyService::class)->change(self::TENANT, $this->connectionId, [
    'enabled'      => true,
    'issuer_class' => 'single_organization',
    'acknowledged' => true,
], $client);

self::assertTrue($changed->isChanged());
```

A member whose verified email the provider asserts is linked on their first sign-in: the completion reserves the link,
and the redemption activates it (see [Linking by a verified domain](linking-by-domain.md)). The member must have joined
the tenant before the domain was verified.

<!-- snippet: tests/Integration/Examples/DomainLinkingExampleTest.php#domain-linking -->

```php
$person = new IdentityReference('App\Models\User', 'person-1');

$this->directory->add($person, 'person@example.com', self::TENANT, $this->clock->now()->subDays(2));

/** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\LinkActivated> $activated */
$activated = new \ArrayObject;

Event::listen(LinkActivated::class, static function (LinkActivated $event) use ($activated): void {
    $activated->append($event);
});

$withEmail = static fn (FakeIdToken $token): FakeIdToken => $token->with('email', 'person@example.com')->with('email_verified', true);
$start     = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
$redirect  = $this->respondAtProvider($this->provider, $this->connectionId, $start, $withEmail);
$signedIn  = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

self::assertEquals($person, $signedIn->linkedIdentity);
self::assertCount(1, $activated);
self::assertSame($signedIn->linkId, $activated->getArrayCopy()[0]->linkId);
```

An email of the domain that no person of yours holds reserves nothing, and the sign-in ends as any unlinked one does:

<!-- snippet: tests/Integration/Examples/DomainLinkingExampleTest.php#domain-linking-refused -->

```php
$stranger = static fn (FakeIdToken $token): FakeIdToken => $token->with('email', 'stranger@example.com')->with('email_verified', true);
$start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
$redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start, $stranger);

self::assertSame(FailureReason::UNLINKED->value, $redirect->error);
```

## Provisioning

A `sign_in` of a subject nobody is linked to is offered to your synchronous listener of `Events\ResultUnlinked`, which
may create a new person and link the result to them through `Provisioning\ProvisioningHelper` (see
[Provisioning](provisioning.md)). Register it on the event's class, never queued:

<!-- snippet: tests/Integration/Examples/ProvisioningExampleTest.php#provisioning -->

```php
$listener = new ProvisionNewPeople;

Event::listen(ResultUnlinked::class, $listener->handle(...));

$start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
$redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);
$signedIn = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

self::assertCount(1, $listener->provisioned());
self::assertEquals($listener->provisioned()[0], $signedIn->linkedIdentity);
```

With no listener, or one that provisions nobody, the sign-in fails `unlinked`, unless your application allows unlinked
handoffs:

<!-- snippet: tests/Integration/Examples/ProvisioningExampleTest.php#provisioning-refused -->

```php
$start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
$redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);

self::assertFalse($redirect->hasCode());
self::assertSame(FailureReason::UNLINKED->value, $redirect->error);
```

## Metadata and discovery

Serve a SAML provider's metadata on the fake fetcher, import it, and save what the administrator accepts (see
[SAML metadata](saml-metadata.md)):

<!-- snippet: tests/Integration/Examples/MetadataExampleTest.php#saml-metadata -->

```php
$idp = new FakeSamlIdentityProvider;

$this->fetcher->respond('https://idp.example.test/metadata', FetchResult::fetched(200, [], $idp->metadata()->toXml()));

$imported = app(MetadataImporter::class)->importUrl(self::TENANT, null, 'https://idp.example.test/metadata', $idp->entityId);
$proposed = $imported->proposed;

self::assertNotNull($proposed);
self::assertSame([$idp->entityId, FakeSamlIdentityProvider::SSO_URL], [$proposed->settings()['idp_entity_id'], $proposed->settings()['sso_url']]);
self::assertCount(1, $proposed->signingCertificates());

$this->fetcher->assertFetched('https://idp.example.test/metadata', FetchPurpose::METADATA);

// The administrator accepts the proposal, having compared the
// fingerprint
$connections  = app(ConnectionService::class);
$connectionId = (string) $connections->create(self::TENANT, 'saml2', 'Imported SAML', $client, $proposed->settings())->connection?->id;

app(KeyService::class)->trustCertificate(self::TENANT, $connectionId, $proposed->signingCertificates()[0]['certificate'], $client);
$connections->enable(self::TENANT, $connectionId, $client);

self::assertTrue($connections->get(self::TENANT, $connectionId)?->usable);
```

A metadata URL that does not answer `2xx` proposes nothing:

<!-- snippet: tests/Integration/Examples/MetadataExampleTest.php#saml-metadata-refused -->

```php
$this->fetcher->respond(self::METADATA_URL, FetchResult::fetched(500, [], 'Internal Server Error'));

$imported = app(MetadataImporter::class)->importUrl(self::TENANT, null, self::METADATA_URL, FakeSamlIdentityProvider::ENTITY_ID);

self::assertTrue($imported->isRefused());
self::assertSame(FailureReason::FETCH_FAILED, $imported->reason);
```

The fake OpenID provider serves its discovery document under its issuer. Import it into a connection, and save the
proposal with the fetch it came from (see [Setting up an OIDC connection](oidc-connections.md)):

<!-- snippet: tests/Integration/Examples/MetadataExampleTest.php#oidc-discovery -->

```php
$provider = (new FakeOpenIdProvider(clock: $this->clock))->serve($this->fetcher);

$connections  = app(ConnectionService::class);
$connectionId = (string) $connections->create(self::TENANT, 'oidc', 'Discovered OIDC', $client, [
    'client_id'     => FakeOpenIdProvider::CLIENT_ID,
    'client_secret' => FakeOpenIdProvider::CLIENT_SECRET,
])->connection?->id;

$imported = app(DiscoveryImporter::class)->import(self::TENANT, $provider->issuer, $connectionId);
$proposed = $imported->proposed;

self::assertNotNull($proposed);
self::assertSame($provider->endpoint('jwks'), $proposed->settings()['jwks_uri']);

$this->fetcher->assertFetched($provider->discoveryUrl(), FetchPurpose::DISCOVERY);
$this->fetcher->assertFetched($provider->endpoint('jwks'), FetchPurpose::JWKS);

app(ImportSaver::class)->save(self::TENANT, $connectionId, ['settings' => $proposed->settings()], $proposed->fetch(), $client);
$connections->enable(self::TENANT, $connectionId, $client);

self::assertTrue($connections->get(self::TENANT, $connectionId)?->usable);
```

A document that names another issuer than the one it was fetched for is refused:

<!-- snippet: tests/Integration/Examples/MetadataExampleTest.php#oidc-discovery-refused -->

```php
$provider = (new FakeOpenIdProvider('https://op.example.test', clock: $this->clock))
    ->withDiscovery(['issuer' => 'https://elsewhere.example.test'])
    ->serve($this->fetcher);

$imported = app(DiscoveryImporter::class)->import(self::TENANT, $provider->issuer);

self::assertTrue($imported->isRefused());
self::assertSame(FailureReason::ISSUER_MISMATCH, $imported->reason);
```

## What the fakes do, and do not, prove

### They refuse what nobody expected

`FakeFetcher` and `FakeDnsResolver` answer only what you gave them. A request to any other URL, or a lookup of any other
name, throws a `LogicException` naming it, so a stray request fails your test instead of passing quietly:

<!-- snippet: tests/Integration/Examples/FakesExampleTest.php#fetcher-unexpected -->

```php
$this->expectException(\LogicException::class);
$this->expectExceptionMessage('FakeFetcher has no response for [https://unknown.example.test/.well-known/openid-configuration].');

app(DiscoveryImporter::class)->import(self::TENANT, 'https://unknown.example.test');
```

<!-- snippet: tests/Integration/Examples/FakesExampleTest.php#resolver-unexpected -->

```php
app(DomainService::class)->claim(self::TENANT, $connectionId, 'example.com', $client);

$this->expectException(\LogicException::class);
$this->expectExceptionMessage('The fake DNS resolver has no answer for [_sso-verification.example.com].');

app(DomainService::class)->verify(self::TENANT, $connectionId, 'example.com', $client);
```

### The fake fetcher proves nothing of the real transport

`FakeFetcher` applies none of the default fetcher's protections. A test through it shows what your application and the
package make of a response; it does not show that a request would be refused for an address on your network, a cloud
metadata address, a redirect, a plain `http` URL or a certificate that does not verify, or that a slow or oversized
response is cut off. Those protections are the default fetcher's own, tested by the package (see
[Outbound requests](outbound-requests.md)). The one check the fake keeps is a request's own size cap: metadata longer
than `sso.metadata.max_bytes` fails as `fetch_failed`. If you bind a fetcher of your own, an egress proxy say, test it
against the real network, not through this fake.

The fake resolver is the same: it proves what the package makes of an answer, not how your resolver behaves when DNS is
slow or down.

### The frozen clock ignores Laravel's time travel

`FrozenClock` holds the instant it was built with until the test moves it with `advance()` or `setTo()`. Once built,
`travelTo()`, `travel()` and `Carbon::setTestNow()` do not move it, and moving it does not move Laravel's time (see
[Clock](clock.md#a-frozen-clock-in-tests)):

<!-- snippet: tests/Integration/Examples/FakesExampleTest.php#frozen-clock -->

```php
$this->travelTo(CarbonImmutable::parse('2027-01-01T00:00:00Z'));

self::assertSame('2027-01-01T00:00:00Z', CarbonImmutable::now('UTC')->toIso8601ZuluString());
self::assertSame('2026-11-01T09:30:00Z', $this->clock->now()->toIso8601ZuluString());

$this->clock->advance(90);

self::assertSame('2026-11-01T09:31:30Z', $this->clock->now()->toIso8601ZuluString());

$this->clock->setTo('2026-11-02T08:00:00Z');

self::assertSame('2026-11-02T08:00:00Z', $this->clock->now()->toIso8601ZuluString());
```

### OIDC reads the clock; SAML takes the instant

The fake OpenID provider is given the clock the package reads, and issues every token at its now, whatever Laravel's
time travel says:

<!-- snippet: tests/Integration/Examples/OidcExampleTest.php#oidc-clock -->

```php
$this->travelTo(CarbonImmutable::parse('2026-11-02T09:30:00Z'));

$this->linkThroughFlow($this->provider, $this->connectionId, $this->person);

$signedIn = $this->signInThroughFlow($this->provider, $this->connectionId, 'session-1');

self::assertTrue($signedIn->isAdmitted());
```

The fake SAML identity provider has no clock: it makes each response at the instant you give `respondTo()` or
`response()`, and at the current time, Laravel's, when you give none. Pass it the package's clock's instant. A response
made at Laravel's time while the package's clock says otherwise is, to the package, from another time, and refused:

<!-- snippet: tests/Integration/Examples/SamlExampleTest.php#saml-instant -->

```php
$this->travelTo(CarbonImmutable::parse('2026-11-02T09:30:00Z'));

$start   = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
$request = $this->idp->receive($start);

// Made at Laravel's time, a day after the package's clock
$response = $this->idp->respondTo($request);
$result   = app(CompletionService::class)->complete(
    CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
    $this->connectionId,
    $response->completionRequest($request->relayState),
    $client,
);

self::assertSame(FailureReason::ASSERTION_EXPIRED, $result->reason);

// Made at the package's clock's instant
$start    = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
$redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);

self::assertTrue($redirect->hasCode());
```

### `FakeFreshness` answers what you tell it

The package's default freshness contract refuses every operation, so a test of a `link` or a management helper binds
`FakeFreshness` (see [Fresh authentication](freshness.md#testing-with-fakefreshness)). `fresh()` lets everything
through, `stale()` refuses everything, and `staleFor()` refuses only the operations it names; it records each operation
it was asked about, with the maximum age:

<!-- snippet: tests/Integration/Examples/FakesExampleTest.php#fake-freshness -->

```php
$this->freshness->staleFor(FreshnessOperation::LINK_CREATE);

$refused = $this->startFlow(Purpose::LINK, $connectionId, $person);

self::assertSame(FailureReason::FRESHNESS_REQUIRED, $refused->reason);
$this->freshness->assertAsked(FreshnessOperation::LINK_CREATE, 300);

self::assertTrue($this->startFlow(Purpose::SIGN_IN, $connectionId)->isStarted());
```

It judges no caller, and records the one each question was asked for (`asked()`). Your own contract judges when the
caller it is given last authenticated.

## Refusals worth testing

Each of these is shown above, and each is a value your code must handle, never an exception:

| What happens                             | How the test makes it                            | What the package answers               |
|------------------------------------------|--------------------------------------------------|----------------------------------------|
| A code redeemed twice                    | Redeem the same redirect again                   | `replayed`                             |
| A response from an untrusted provider    | `signedBy()` another provider's signer           | A failed redirect, `signature_invalid` |
| An ID token signed by an unpublished key | A tailor that calls `signedWith()`               | A failed redirect, `signature_invalid` |
| A `link` redeemed by someone else        | Redeem with another caller                       | `identity_mismatch`                    |
| A code at the wrong endpoint             | Admit a `reauthenticate` code as a `sign_in`     | `purpose_mismatch`                     |
| A session not signed in                  | Start a `reauthenticate` for another session     | A refused start, `session_ineligible`  |
| A stale caller                           | `FakeFreshness::staleFor()`                      | A refused start, `freshness_required`  |
| An unknown subject                       | Sign in with no link and no listener             | A failed redirect, `unlinked`          |
| A response from another time             | A SAML response made without the clock's instant | `assertion_expired`                    |
| An unsolicited response posted twice     | Post the same response again                     | A rejected completion, `replayed`      |
| A record not yet published               | `FakeDnsResolver::absent()`                      | `domain_record_not_found`              |
| A metadata URL that fails                | A `5xx` from the fake fetcher                    | `fetch_failed`                         |
| A document for another issuer            | `withDiscovery(['issuer' => ...])`               | `issuer_mismatch`                      |

The hostile SAML responses (`Saml\SignatureWrapping`, duplicate ids, comments in a `NameID`, weak algorithms) and ID
tokens (`Oidc\HostileIdTokens`) are the package's adversarial suite; your tests need them only to show your own code
handles the failure each ends with.

## Keeping the examples honest

The examples run with the package's Integration suite. Two checks keep them what this guide says:

- `tests/Unit/Documentation/ExampleSnippetsTest.php` reads every `<!-- snippet: <path>#<region> -->` marker in the
  guides and the README, and fails when the fenced block after it is not exactly that region of that source, or when an
  example's region is shown nowhere. A region is the lines between `// @snippet-start <region>` and
  `// @snippet-end <region>`, with their shared indentation removed; as with any inline comment, no blank line follows
  either.
- `tests/Unit/Documentation/ExamplesUsePublicApiTest.php` fails when an example names a class of the package marked
  `@internal`, a model, or a test trait or fixture of the package's, reads a table or builds a verified result, and
  when a public testing helper is missing from this guide.

Any guide can show an executable example the same way: put the code in a test under `tests/Integration/Examples`,
extending `ExampleTestCase`, mark the region, and put the marker before its snippet.
