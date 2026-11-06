# An Example Application

The package adds no routes, controllers or views: your API calls one helper per endpoint and turns the value it answers
into a response. This guide lays out one coherent API that serves every flow (SSO-12.5): which routes are public, which
belong to the authenticated caller, which are for administrators, how each fixes its purpose, how the base URL accounts
for Laravel's API prefix, and what the client does.

The code below is not a sketch. It is the package's executable example, in `tests/Integration/Examples/Routes`, which
`RouteLayoutExampleTest` runs over HTTP on the shared example harness of [Testing](testing.md), so what this guide shows
is what the package does. Its controllers call the package's public helpers alone. `Caller`, `SignIns`, `Answers`,
`ConnectionTenants` and `User` are the example application's own: replace them with your authentication, sessions and
tenancy.

## The routes

| Method   | Path                                                                    | Access          | Calls                                                    |
|----------|-------------------------------------------------------------------------|-----------------|----------------------------------------------------------|
| `POST`   | `/api/auth/sso/authorization-requests`                                  | public          | `AuthorizationRequestService::start()`, or discovery     |
| `POST`   | `/api/auth/sso/connections/{connection}/assertions`                     | public, no CSRF | `CompletionService::complete()`, the ACS                 |
| `GET`    | `/api/auth/sso/connections/{connection}/callback`                       | public          | `CompletionService::complete()`, the callback            |
| `GET`    | `/api/auth/sso/connections/{connection}/metadata`                       | public          | `ServiceProviderDescriptions::describe()`                |
| `GET`    | `/api/auth/sso/connections/{connection}/jwks`                           | public          | `ServiceProviderDescriptions::publicKeys()`              |
| `POST`   | `/api/auth/sessions`                                                    | public          | `HandoffRedemption::admit()`, `sign_in` only             |
| `POST`   | `/api/auth/sso/links/authorization-requests`                            | caller          | `AuthorizationRequestService::start()`, `link` only      |
| `POST`   | `/api/auth/sso/links`                                                   | caller          | `HandoffRedemption::redeem()`, `link` only               |
| `GET`    | `/api/auth/sso/links`                                                   | caller          | `LinkService::list()`                                    |
| `DELETE` | `/api/auth/sso/links/{link}`                                            | caller          | `LinkService::remove()`                                  |
| `POST`   | `/api/auth/sso/reauthentications/authorization-requests`                | caller          | `AuthorizationRequestService::start()`, `reauthenticate` |
| `POST`   | `/api/auth/sso/reauthentications`                                       | caller          | `HandoffRedemption::admit()`, `reauthenticate` only      |
| `*`      | `/api/auth/sso/connections[/{connection}]`                              | administrator   | `ConnectionService`, `ConnectionLifecycle`               |
| `POST`   | `/api/auth/sso/connections/{connection}/domains`                        | administrator   | `DomainService::claim()`                                 |
| `DELETE` | `/api/auth/sso/connections/{connection}/domains/{domain}`               | administrator   | `DomainService::remove()`                                |
| `POST`   | `/api/auth/sso/connections/{connection}/domains/{domain}/verifications` | administrator   | `DomainService::verify()`                                |

This differs from the sketch in SSO-12.5 in one respect, on purpose: that sketch starts every flow at one endpoint
whose body names the purpose. Here each purpose has its own endpoint, which fixes it server side, so a `link` or a
`reauthenticate` start sits behind your authentication and takes its identity and session from it, and a body can never
turn a sign-in into something else. Under `laravel-iam`, `POST /api/auth/sessions` and the re-authentication redemption
are `laravel-authentication`'s routes, and its adapter calls the package (see
[Under `laravel-iam`](#under-laravel-iam)).

## The base URL and the API prefix

Laravel serves `routes/api.php` under `/api` (`php artisan install:api` creates it, and `withRouting(api: ...)` in
`bootstrap/app.php` registers it with that prefix). The package builds every URL it gives an identity provider (the
assertion consumer service, the callback, the metadata URL, which is also the SAML entity id, and the public JWKS) from
`sso.endpoints.base_url` followed by the path patterns of `sso.endpoints.paths`, never from the request. So the base URL
carries the prefix, as `SSO_BASE_URL=https://sp.example.test/api` in `.env` does:

<!-- snippet: tests/Integration/Examples/Routes/RouteLayoutExampleTest.php#route-base-url -->
```php
config()->set('sso.endpoints.base_url', 'https://sp.example.test/api');
```

With the default paths, the connection `01k…` then has its assertion consumer service at
`https://sp.example.test/api/auth/sso/connections/01k…/assertions`, which is the route below. Leave the base URL without
the prefix and every identity provider is given URLs your API does not serve. Decide the layout before you register the
first connection: the URLs are what administrators enter at their identity providers, and the SAML entity id is one of
them, so moving them later means registering every connection again. See [Configuration](configuration.md#endpoints).

## The routes file

<!-- snippet: tests/Integration/Examples/Routes/routes.php#route-layout -->
```php
Route::post('/auth/sso/authorization-requests', [SsoStartController::class, 'signIn']);
Route::post('/auth/sso/connections/{connection}/assertions', [SsoCompletionController::class, 'assertion']);
Route::get('/auth/sso/connections/{connection}/callback', [SsoCompletionController::class, 'callback']);
Route::get('/auth/sso/connections/{connection}/metadata', [SsoMetadataController::class, 'metadata']);
Route::get('/auth/sso/connections/{connection}/jwks', [SsoMetadataController::class, 'jwks']);
Route::post('/auth/sessions', [SsoSessionController::class, 'store']);

Route::middleware('auth')->group(static function (): void {
    Route::post('/auth/sso/links/authorization-requests', [SsoStartController::class, 'link']);
    Route::post('/auth/sso/links', [SsoLinkController::class, 'store']);
    Route::get('/auth/sso/links', [SsoLinkController::class, 'index']);
    Route::delete('/auth/sso/links/{link}', [SsoLinkController::class, 'destroy']);
    Route::post('/auth/sso/reauthentications/authorization-requests', [SsoStartController::class, 'reauthenticate']);
    Route::post('/auth/sso/reauthentications', [SsoReauthenticationController::class, 'store']);
});

Route::middleware(['auth', 'can:manage-sso'])->group(static function (): void {
    Route::get('/auth/sso/connections', [SsoConnectionController::class, 'index']);
    Route::post('/auth/sso/connections', [SsoConnectionController::class, 'store']);
    Route::get('/auth/sso/connections/{connection}', [SsoConnectionController::class, 'show']);
    Route::patch('/auth/sso/connections/{connection}', [SsoConnectionController::class, 'update']);
    Route::delete('/auth/sso/connections/{connection}', [SsoConnectionController::class, 'destroy']);
    Route::post('/auth/sso/connections/{connection}/enable', [SsoConnectionController::class, 'enable']);
    Route::post('/auth/sso/connections/{connection}/disable', [SsoConnectionController::class, 'disable']);
    Route::post('/auth/sso/connections/{connection}/domains', [SsoDomainController::class, 'store']);
    Route::delete('/auth/sso/connections/{connection}/domains/{domain}', [SsoDomainController::class, 'destroy']);
    Route::post('/auth/sso/connections/{connection}/domains/{domain}/verifications', [SsoDomainController::class, 'verify']);
});
```

Three groups, three kinds of access:

- **Public.** The start of a sign-in, the completion routes, the metadata and the public keys, and the sign-in
  redemption take no session and no authentication. The completion routes are reached by the identity provider's
  redirect or post, and the package checks the response itself; the metadata and the keys hold nothing secret; the
  redemption is authenticated by the code and its verifier.
- **The caller's own.** Linking and re-authentication act for the identity your authentication established, on the
  session it established. They take both from the authentication, never from the request body.
- **Management.** Connections and domains are changed by an administrator of the tenant the caller is active in, behind
  your authorisation as well as the authentication.

## Cross-site request forgery

The SAML response arrives as a cross-site `POST`: the identity provider's page posts it from the browser, so it can
carry no CSRF token. Exempt that route, and only that one:

<!-- snippet: tests/Integration/Examples/Routes/RouteLayoutExampleTest.php#route-csrf -->
```php
// In bootstrap/app.php, inside the withMiddleware() callback
$middleware->preventRequestForgery(except: ['api/auth/sso/connections/*/assertions']);
```

On Laravel 12, call `validateCsrfTokens()` with the same `except`; Laravel 13 keeps it as a deprecated name for
`preventRequestForgery()`. The example reads the exemption back from the framework's CSRF middleware and holds it to the
assertion consumer service alone.

Routes in `routes/api.php` are outside the `web` group, where Laravel's CSRF verification runs. If your API
authenticates by cookie, through the `web` group or a stateful API guard for a first-party single-page application, the
verification runs on its routes too, and the exemption keeps it off the assertion consumer service alone. Never widen it
to `api/auth/*` or `api/auth/sso/*`: the sign-in redemption, the link and re-authentication routes and every management
route would then accept a cross-site request a cookie authenticates. The OIDC callback is a `GET` and needs no
exemption.

## Starting a flow: one endpoint per purpose

A sign-in names a connection, or an email address whose verified domain finds one ([Discovery](discovery.md)):

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoStartController.php#route-start-sign-in -->
```php
/** @var array{application: string, connection?: string, email?: string, code_challenge?: ?string} $input */
$input = Validator::validate($request->all(), [
    'application'    => ['required', 'string'],
    'connection'     => ['required_without:email', 'string'],
    'email'          => ['required_without:connection', 'string', 'max:320'],
    'code_challenge' => ['nullable', 'string'],
]);

$challenge = $input['code_challenge'] ?? null;

// The purpose is this endpoint's: a `purpose` in the body is never read
$result = isset($input['email'])
    ? $this->discovery->start($input['application'], Purpose::SIGN_IN, $input['email'], ClientContext::fromRequest($request), $challenge)
    : $this->requests->start($input['application'], Purpose::SIGN_IN, $input['connection'] ?? '', ClientContext::fromRequest($request), $challenge);
```

A link and a re-authentication take the caller's identity, and a re-authentication the caller's session, from the
authentication:

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoStartController.php#route-start-link -->
```php
$input = self::input($request);

$result = $this->requests->start(
    $input['application'],
    Purpose::LINK,
    $input['connection'],
    ClientContext::fromRequest($request),
    $input['code_challenge'] ?? null,
    Caller::identity($request),
);
```

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoStartController.php#route-start-reauthenticate -->
```php
$input = self::input($request);

$result = $this->requests->start(
    $input['application'],
    Purpose::REAUTHENTICATE,
    $input['connection'],
    ClientContext::fromRequest($request),
    $input['code_challenge'] ?? null,
    Caller::identity($request),
    Caller::sessionId($request),
);
```

Every start answers the same way, with the headers the result carries (`Cache-Control: no-store`, since a started answer
may carry the verifier, and `Retry-After` when it is rate limited):

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoStartController.php#route-start-answer -->
```php
$status = match (true) {
    $result->isStarted()     => 200,
    $result->isRateLimited() => 429,
    default                  => 400,
};

return response()->json($result->body(), $status, $result->headers());
```

The application name comes from the client and is matched exactly against `sso.applications`; nothing else in the body
chooses anything. The package's default contracts refuse a `link` (freshness and eligibility) and a `reauthenticate`
(your sessions) until you bind your own; see [Starting a flow](starting-a-flow.md#purposes).

## Completing a flow

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoCompletionController.php#route-assertion -->
```php
$result = $this->completions->complete(
    CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
    $connection,
    CompletionRequest::fromRequest($request),
    ClientContext::fromRequest($request),
);

return $this->responses->from($result, $request->getMethod());
```

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoCompletionController.php#route-callback -->
```php
$result = $this->completions->complete(
    CompletionEndpoint::CALLBACK,
    $connection,
    CompletionRequest::fromRequest($request),
    ClientContext::fromRequest($request),
);

return $this->responses->from($result, $request->getMethod());
```

A completion redirects to your application's registered redirect URI with the code and the request's reference, or with
an error code; answers `400` when nothing names a trusted redirect target; and `429` when its limit is full. Never wrap
these routes in a transaction of your own. See [Completing a flow](completing-a-flow.md) and
[Completion responses](completion-responses.md).

## Signing in: pending sessions, and no credential before the commit

The sign-in route redeems `sign_in` codes only, inside your own transaction on the package's storage connection, and
writes the session in that same transaction:

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoSessionController.php#route-sign-in -->
```php
/** @var array{application: string, connection: string, code: string, verifier: string} $input */
$input = Validator::validate($request->all(), [
    'application' => ['required', 'string'],
    'connection'  => ['required', 'string'],
    'code'        => ['required', 'string'],
    'verifier'    => ['required', 'string'],
]);

$client = ClientContext::fromRequest($request);

// The code is consumed and the session written in one transaction, on
// the package's storage connection
[$result, $sessionId] = DB::connection(StorageConnection::name())->transaction(function () use ($input, $client): array {
    $result = $this->redemptions->admit(Purpose::SIGN_IN, $input['application'], $input['connection'], $input['code'], $input['verifier'], $client);

    // Active, or pending your own further factor; an unlinked handoff
    // signs nobody in
    $sessionId = $result->isRedeemed() && $result->linkedIdentity !== null ? $this->signIns->start($result) : null;

    return [$result, $sessionId];
});

// Only now, after the commit, does a credential leave
return $sessionId === null
    ? self::refusal($result)
    : response()->json($this->signIns->credential($sessionId), 200, Answers::NO_STORE);
```

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoSessionController.php#route-sign-in-refusal -->
```php
return $result->isRateLimited() ? Answers::rateLimited($result->retryAfter) : Answers::refused($result->reason ?? FailureReason::UNLINKED);
```

- **One transaction.** The code's consumption, any reservation's activation and your session commit or roll back
  together, and the locks the redemption takes (the tenant's enforcement, the connections, the link) are held until your
  commit, so a change to enforcement or to the link either waits for your session or is seen by the redemption. A
  transaction on another Laravel connection is not atomic with it (decision D5).
- **No credential before the commit.** The token is issued only once the transaction has committed. A credential sent
  from inside it would outlive a rollback.
- **Pending is an outcome, not a failure.** The example writes the session `pending`, so your own further factor is
  still due, unless its own further-factor policy is satisfied by the methods of the evidence the package accepted
  ([Evidence](evidence.md)), never because evidence was accepted at all. A pending session commits with the redemption
  like an active one; its credential admits only the further factor. Under `laravel-iam`, `laravel-authentication`
  decides whether a session is pending.
- **A refusal commits, an exception rolls back.** A refused code is spent and the client starts again; a database error
  or a contract that throws rolls everything back and leaves the code unspent.
- **Unlinked handoffs.** This application leaves `unlinked_handoffs` off, so every code it redeems names an identity.
  An application that allows them resolves the identity itself here, never from the email or another attribute.

The example's further-factor policy is its own: the connections it trusts for that factor, which it chooses, and the
RFC 8176 methods it counts as one (`SignIns::FURTHER_FACTOR_METHODS`: `hwk`, `mfa`, `otp`, `sc` and `swk`). Evidence
from any other connection, or stating only `pwd`, leaves the session pending:

<!-- snippet: tests/Integration/Examples/Routes/Application/SignIns.php#route-further-factor -->
```php
$evidence = $redemption->evidence;

// Accepted evidence is an input to your own policy, never a pass: count
// it only from a connection you trust for the further factor, and only
// for a method you count as one
if ($evidence === null || !isset($this->furtherFactorConnections[$evidence->connectionId])) {
    return false;
}

return array_intersect($evidence->methods(), self::FURTHER_FACTOR_METHODS) !== [];
```

The session also keeps how it began. `SignIns::start()` writes the provenance the redemption captured with the session,
in the same transaction, once:

<!-- snippet: tests/Integration/Examples/Routes/Application/SignIns.php#route-provenance-capture -->
```php
// Written once, with the session, in the redemption's transaction;
// never rewritten, not even by a re-authentication
$this->provenance[$sessionId] = $redemption->provenance?->toArray();
```

and a later request projects it into the `sso.*` authentication context, which is empty for a session the package did
not establish:

<!-- snippet: tests/Integration/Examples/Routes/Application/SignIns.php#route-provenance-project -->
```php
return AuthenticationContext::fromStored($this->provenance[$sessionId] ?? null);
```

The keys say how the session began, never whether it is still allowed: see
[Session Provenance and the Authentication Context](session-provenance.md).

See [Redeeming a handoff](redeeming-a-handoff.md) for every check a redemption makes and every refusal.

## Linking an identity

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoLinkController.php#route-link -->
```php
/** @var array{application: string, connection: string, code: string, verifier: string} $input */
$input = Validator::validate($request->all(), [
    'application' => ['required', 'string'],
    'connection'  => ['required', 'string'],
    'code'        => ['required', 'string'],
    'verifier'    => ['required', 'string'],
]);

// A `link` writes no session, so it is redeemed alone, for the caller
// the application authenticated
$result = $this->redemptions->redeem(
    Purpose::LINK,
    $input['application'],
    $input['connection'],
    $input['code'],
    $input['verifier'],
    ClientContext::fromRequest($request),
    Caller::identity($request),
);

return match (true) {
    $result->isRedeemed()    => response()->json(['link' => $result->linkId], 201, Answers::NO_STORE),
    $result->isRateLimited() => Answers::rateLimited($result->retryAfter),
    default                  => Answers::refused($result->reason ?? FailureReason::HANDOFF_UNKNOWN),
};
```

A `link` writes no session, so it is redeemed alone, with no transaction of yours open, for the caller your
authentication established: holding the code and its verifier proves which client started the flow, not who is calling
now. Never sign anyone in from its result. The caller lists their own links, and removes only a link of their own:

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoLinkController.php#route-links -->
```php
return response()->json($this->links->list('me', Caller::identity($request)), 200, Answers::NO_STORE);
```

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoLinkController.php#route-link-remove -->
```php
$result = $this->links->remove('me', $link, ClientContext::fromRequest($request), Caller::identity($request), Caller::actor($request));

return Answers::of($result, 200);
```

Passing `'me'` with the caller limits the removal to the caller's links, and a link of anyone else answers as unknown.
A removal asks the freshness contract and revokes the identity's sessions through the connection; see
[Links](links.md).

## Re-authenticating

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoReauthenticationController.php#route-reauthenticate -->
```php
/** @var array{application: string, connection: string, code: string, verifier: string} $input */
$input = Validator::validate($request->all(), [
    'application' => ['required', 'string'],
    'connection'  => ['required', 'string'],
    'code'        => ['required', 'string'],
    'verifier'    => ['required', 'string'],
]);

// The package renews the code's session inside this transaction, once; nothing renews it again
$result = DB::connection(StorageConnection::name())->transaction(
    fn (): RedemptionResult => $this->redemptions->admit(
        Purpose::REAUTHENTICATE,
        $input['application'],
        $input['connection'],
        $input['code'],
        $input['verifier'],
        ClientContext::fromRequest($request),
    ),
);

// The code renewed the session it was started on: only when that is the
// caller's own is the caller fresh
$renewed = $result->isRedeemed() && $result->sessionId === Caller::sessionId($request);

return match (true) {
    $renewed                 => response()->json(['status' => 'reauthenticated'], 200, Answers::NO_STORE),
    $result->isRateLimited() => Answers::rateLimited($result->retryAfter),
    default                  => Answers::refused($result->reason ?? FailureReason::SESSION_INELIGIBLE),
};
```

The package renews the session the code is bound to inside `admit()`, once, through your `ReauthenticationSessions`
binding, under its locks: nothing in your route renews it again. A code renews the session it was started on, so the
route tells the caller they are fresh only when that is the session they are using. See
[Re-authenticating](reauthenticating.md).

## Service provider metadata and keys

An identity provider fetches a connection's metadata with no authentication, naming the connection and no tenant, while
the package's helpers are scoped to a tenant. In a service provider's `boot()`, the example keeps its own record of each
connection's tenant from the package's events, and authorises management with a gate:

<!-- snippet: tests/Integration/Examples/Routes/RouteLayoutExampleTest.php#route-tenants -->
```php
Event::listen(ConnectionCreated::class, [ConnectionTenants::class, 'remember']);
Event::listen(ConnectionDeleted::class, [ConnectionTenants::class, 'forget']);

// Who may manage the single sign-on of the tenant they are active in is
// the application's decision
Gate::define('manage-sso', static fn (User $user): bool => $user->administersSso());
```

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoMetadataController.php#route-metadata -->
```php
$tenantId    = $this->tenants->of($connection);
$description = $tenantId === null ? null : $this->descriptions->describe($tenantId, $connection);

if ($description === null || !$description->isAvailable()) {
    abort(404);
}

return response((string) $description->body, 200, [
    'Content-Type'  => (string) $description->contentType,
    'Cache-Control' => 'public, max-age=3600',
]);
```

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoMetadataController.php#route-jwks -->
```php
$keys = $this->descriptions->publicKeys($connection);

if (!$keys->isAvailable()) {
    abort(404);
}

return response((string) $keys->body, 200, ['Content-Type' => (string) $keys->contentType, 'Cache-Control' => 'public, max-age=300']);
```

A connection unknown to the tenant, or to your record, answers the same `404`. Keep any cache lifetime well inside
your key overlap. See [Service provider metadata](service-provider-metadata.md).

## Management: authorisation and ownership

Every management route takes the tenant from the caller's active tenant, never from the request:

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoConnectionController.php#route-connection-create -->
```php
/** @var array{protocol: string, display_name: string, settings?: array<string, mixed>, attribute_mapping?: array<string, string>, preset?: ?string} $input */
$input = Validator::validate($request->all(), [
    'protocol'          => ['required', 'string'],
    'display_name'      => ['required', 'string'],
    'settings'          => ['array'],
    'attribute_mapping' => ['array'],
    'preset'            => ['nullable', 'string'],
]);

// The tenant is the caller's active one, never the body's
$result = $this->connections->create(
    tenantId: Caller::tenantId($request),
    protocol: $input['protocol'],
    displayName: $input['display_name'],
    client: ClientContext::fromRequest($request),
    settings: $input['settings']                  ?? [],
    attributeMapping: $input['attribute_mapping'] ?? [],
    preset: $input['preset']                      ?? null,
    actor: Caller::actor($request),
);

return Answers::of($result, 201);
```

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoConnectionController.php#route-connection-show -->
```php
$summary = $this->connections->get(Caller::tenantId($request), $connection);

if ($summary === null) {
    abort(404); // unknown, or another tenant's: the same answer
}

return response()->json($summary, 200, Answers::NO_STORE);
```

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoDomainController.php#route-domain-claim -->
```php
/** @var array{domain: string} $input */
$input  = Validator::validate($request->all(), ['domain' => ['required', 'string', 'max:253']]);
$result = $this->domains->claim(Caller::tenantId($request), $connection, $input['domain'], ClientContext::fromRequest($request), Caller::actor($request));

// The token is shown to the administrator to publish, and never logged
$record = $result->domain === null ? null : ['name' => $result->domain->recordName, 'value' => $result->domain->verificationToken()];

return Answers::of($result, 201, ['domain' => $result->domain, 'record' => $record]);
```

- **Authorisation is yours.** The `manage-sso` gate decides who administers the active tenant's single sign-on. The
  package asks your freshness contract before a change that could widen or redirect access, and refuses a stale caller
  with `freshness_required`, but freshness says when the caller authenticated, not what they may do.
- **Ownership is the tenant id you pass.** Every helper is scoped to it, and answers another tenant's connection or
  domain exactly as an unknown one, so a caller of one tenant never learns of another's.
- **Secrets stay in.** A connection's secret is accepted in a request and never returned: its summary says only whether
  it is set.

The example's `Answers` maps the package's results to statuses:

| Result                                                       | Status                                    |
|--------------------------------------------------------------|-------------------------------------------|
| succeeded (created, updated, unchanged, enabled, …)          | `200`, or `201` for a creation or a claim |
| invalid, with its violations                                 | `422`                                     |
| `freshness_required`                                         | `403`: authenticate again, then retry     |
| `connection_not_found`, `domain_not_found`, `link_not_found` | `404`                                     |
| `rate_limited`                                               | `429`, with `Retry-After`                 |
| any other refusal                                            | `409`                                     |

## The client's part

The handoff is bound to the client that started the flow by a verifier, as PKCE does, and that holds only while the
client does its part (SSO-5.12):

- generate a fresh verifier for each start (43 to 128 unreserved characters with at least 256 bits of entropy), or let
  the package generate it, and send only its S256 challenge;
- keep the verifier with the request's public reference, in memory or storage scoped to the application;
- redeem only a handoff whose reference matches a request it started;
- send the code and the verifier in a `POST` body, never in a URL;
- remove the code from the address bar and the history at once.

[Starting a flow](starting-a-flow.md#the-clients-duties) states each duty in full, and
[Completion responses](completion-responses.md#what-your-client-does-with-the-fragment) shows a client reading the
redirect.

## What the example leaves to you

- **Your contracts.** Bind the link store as `Linker`, and your own freshness, link eligibility, re-authentication
  sessions and session revocation: each default refuses or does nothing. See [Installation](installation.md) and the
  guide of each flow.
- **Your sessions and credentials.** `SignIns` stands for your sign-in. The package never issues your tokens or creates
  your sessions.
- **Your tenancy.** `Caller` reads the caller's active tenant and session from your authentication, and
  `ConnectionTenants` is your record of each connection's tenant.
- **Your throttles.** The package rate limits starts, completions, redemptions, metadata fetches and domain checks; add
  your own limits to the routes as you would to any other.

## Under `laravel-iam`

`laravel-iam` binds the package's contracts to `laravel-authentication` and `laravel-mfa`, and the sign-in and the
re-authentication redemptions become `laravel-authentication`'s routes. Its adapter opens the transaction, calls the
package's `admit()`, then `laravel-authentication`'s external sign-in or re-authentication entry point once, in that
same transaction, and sends the credential only after the commit. A re-authentication is asked for once, inside
`admit()`, through `ReauthenticationSessions::renewAuthentication()`: the adapter records it there and writes it once,
through `laravel-authentication`'s re-authentication entry point, never a second time. The package issues, stores and
redeems every handoff code there too. See [Integrating with `laravel-iam`](integrating-with-laravel-iam.md).
