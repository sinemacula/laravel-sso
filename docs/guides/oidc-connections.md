# Setting Up An OIDC Connection

An OpenID provider describes itself in a discovery document at a well-known URL under its issuer: where to send people
to sign in, where to exchange the code, where its keys are, and what it supports. The package can fill a connection in
from that document, keep the endpoints and keys up to date on a schedule when you switch it on, and refetch the keys
when an ID token names one it does not hold yet. See [Managing connections](managing-connections.md#oidc-settings) for
every setting and [OIDC sign-in](oidc-sign-in.md) for the flow itself.

## Import

`DiscoveryImporter` fetches the document and the keys and answers what they propose. Nothing is written or trusted: you
show the proposal to the administrator, and save what they accept.

```php
use SineMacula\Laravel\Sso\Metadata\DiscoveryImporter;

$result = app(DiscoveryImporter::class)->import(
    tenantId: $tenant->id,
    issuer: 'https://login.example.com/tenant-a',
    connectionId: $connection->id, // or leave it out before the connection exists
);

if ($result->isRateLimited()) {
    return back()->withErrors(['issuer' => "Try again in {$result->retryAfter} seconds."]);
}

if ($result->isRefused()) {
    return back()->withErrors(['issuer' => $result->reason->value]);
}

$proposed = $result->proposed;

$proposed->settings();    // ['issuer' => ..., 'authorization_endpoint' => ..., 'token_endpoint' => ...,
                          //  'jwks_uri' => ..., 'userinfo_endpoint' => ..., 'returns_iss' => true,
                          //  'id_token_algorithms' => ['RS256', 'ES256']]
$proposed->authMethods(); // ['client_secret_basic', 'private_key_jwt']
$proposed->keys();        // [['kid' => 'abc', 'kty' => 'RSA', 'alg' => 'RS256'], ...]
```

The document is fetched from the issuer with `/.well-known/openid-configuration` appended, path included, so
`https://login.example.com/tenant-a` is read from `https://login.example.com/tenant-a/.well-known/openid-configuration`.
Its `issuer` must equal the one you gave exactly: case, a trailing slash and the path all matter, because every ID token
is later held to that same string. Give the issuer the provider documents, not one you normalised.

An import fetches while you call it, and refuses to run inside a database transaction. Naming a connection holds the
keys to that connection's own allowed algorithms and counts the import against `sso.rate_limits.metadata` (10 an hour
per connection by default) before anything is fetched. An import reports no event.

| Reason                 | When                                                                                                                                                                                       |
|------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `protocol_unavailable` | The `oidc` feature is off: nothing is looked up or fetched                                                                                                                                 |
| `settings_invalid`     | The issuer is not an `https` URL with a host and no query, userinfo or fragment                                                                                                            |
| `connection_not_found` | The connection named is unknown, another tenant's, or not an OIDC connection                                                                                                               |
| `fetch_refused`        | A URL is not `https`, or resolves or redirects to an address the fetcher refuses                                                                                                           |
| `fetch_failed`         | The request failed, timed out, was larger than its cap, or did not answer `2xx`                                                                                                            |
| `issuer_mismatch`      | The document names another issuer                                                                                                                                                          |
| `discovery_invalid`    | Not one JSON object, a member given twice, an endpoint that is not `https`, or a member of the wrong type; no `code` response type; PKCE without `S256`; no algorithm the package supports |
| `jwks_invalid`         | Not one JSON object, a member given twice, more keys than `sso.oidc.max_jwks_keys`, two usable keys under one `kid`, or no usable key                                                      |

A key the package never uses is left out of `keys()` rather than refusing the document: a symmetric (`oct`) key, a
private key, an encryption key, an RSA key under 2048 bits, or an `alg` its curve does not fit.

## Review

Show the administrator what the proposal would save, and in particular:

- the **endpoints**, each on a host they expect. The document is only as trustworthy as the connection to the issuer's
  URL, and an endpoint elsewhere is worth a question;
- the **key ids**, against what the provider publishes;
- `returns_iss`, which makes the callback require the RFC 9207 `iss` parameter;
- the **algorithms**, narrowed to the ones this provider really signs with if you can. The list decides what a token may
  be signed by, so a shorter one is safer.

## Save with freshness

Saving is an ordinary update, and every setting in the proposal is a trust change, so it asks the freshness contract as
`sso.connection.trust`:

```php
use SineMacula\Laravel\Sso\Connections\ConnectionService;

app(ConnectionService::class)->update($tenant->id, $connection->id, [
    'settings' => [...$proposed->settings(), 'client_id' => $clientId, 'client_secret' => $secret],
], $actor);
```

The keys are not saved with it. The first ID token's unknown `kid` fetches them, so a connection with no stored keys is
complete, and enabling it needs nothing more.

Changing `issuer` or `jwks_uri` later clears the stored keys and their cooldown in the same transaction, so keys fetched
for another issuer or URL are never used, and the next ID token fetches from the new URL at once. Changing `issuer` also
clears when the document was last validated and when it next refreshes. The issuer changes what a subject means, so on a
connection with links it needs a [subject migration](managing-connections.md#migrating-subjects).

## Client authentication

A connection authenticates at the token endpoint by exactly one method. `authMethods()` lists what the provider
supports; the import never chooses for you.

| `client_authentication` | What it needs                                                                                              |
|-------------------------|------------------------------------------------------------------------------------------------------------|
| `client_secret_basic`   | `client_secret`; sent in the `Authorization` header. The default                                           |
| `client_secret_post`    | `client_secret`; sent in the form                                                                          |
| `private_key_jwt`       | A current `KeyUse::CLIENT_ASSERTION` key, whose public JWKS you register with the provider; no secret held |

See [The OIDC callback](oidc-callback.md#private_key_jwt) for rotating a `private_key_jwt` key, and [OIDC
sign-in](oidc-sign-in.md) for what makes a connection complete.

## Scheduled refresh

Refreshing is off unless you switch it on, for the application and then per connection:

```dotenv
SSO_METADATA_REFRESH=true
```

```php
app(ConnectionService::class)->update(
    $tenant->id,
    $connection->id,
    ['settings' => ['metadata_refresh' => true]],
    $actor,
);
```

Run `sso:metadata:refresh` from the scheduler and a queue worker for the queue it sends to, exactly as for [SAML
metadata](saml-metadata.md#refreshing-on-a-schedule): the command, the queue, the backoff (5 minutes doubling to 6
hours) and the daily cadence are shared. `refreshNow()` refreshes a connection for an administrator, skipping the
backoff but never another server's claim, rate limited by `sso.rate_limits.metadata`.

A refresh reads only the saved issuer's document, so a document naming another issuer is refused and a refresh never
moves the issuer. It may change only:

- `authorization_endpoint`, `token_endpoint`, `jwks_uri` and `userinfo_endpoint`, set or changed, never removed;
- `returns_iss`, from false to true, never back;
- the stored keys, replaced exactly by what the JWKS publishes now.

It never touches the client id or authentication, the secret, the scopes, the allowed algorithms, the mapping, what a
subject means or enforcement. A refresh that only adds keys (a provider publishing its next key) leaves the flows in
flight alone. One that changes a setting, removes a key or replaces a key under the same `kid` voids them and raises the
connection's trust version, once. Each change is reported: `ConnectionUpdated` for the settings, then
`MetadataRefreshed` naming them and `jwks`, or `MetadataRefreshFailed` (see [Events](events.md)).

A failed refresh keeps the last good settings and keys. A connection that fetches UserInfo needs the endpoint: a
document without one fails the refresh with `discovery_invalid` rather than losing it.

### The 30-day stale limit

What a refresh wrote stops being used once it is too old. The discovery document and the JWKS are counted separately,
each **from its own last validated fetch**, not from when the refresh committed: a refresh stamps both, and an
unknown-`kid` refetch stamps the JWKS alone. Past `sso.metadata.stale_limit_seconds` (30 days by default) every start
and completion through the connection is `metadata_expired` until a refresh succeeds. The expired values stay stored,
for diagnosis.

A connection with `metadata_refresh` off that no refresh has written never expires, since its settings were entered or
imported by hand: nothing has promised they stay current. With `metadata_refresh` on, the JWKS counts as soon as it has
been fetched, even if no refresh has succeeded yet, so switching the refresh on for a connection whose keys are already
over the limit refuses its flows until the first refresh succeeds. Setting the limit to `0` turns it off, which you must
do explicitly and which we do not recommend: a provider that stops publishing a compromised key would then go unnoticed
by a connection whose refresh has been failing for months.

## The refetch cooldown

When an ID token names a `kid` the connection does not hold, the JWKS is fetched again once, so a provider can rotate
its keys without you doing anything. At most one such fetch happens per connection per
`sso.oidc.jwks_refetch_cooldown_seconds` (a minute to an hour, 300 seconds by default).

The cooldown is claimed atomically **before** the fetch, and a failed fetch consumes it too. That is deliberate. Anyone
can send a callback with a token naming a random `kid`, before its signature has been checked, so without the cooldown a
flood of them would turn your servers into a load generator against the provider, and a slow provider into a queue of
stuck requests. With it, a hundred unknown `kid`s make one fetch, however many servers they arrive at.

What that means in practice:

- A key the provider publishes moments after the cooldown was consumed is not found until the cooldown ends: sign-ins
  signed by it fail in the meantime. Providers publish a key well before signing with it, and the scheduled refresh
  picks it up too, so this is rare. Lower the cooldown only if it bites; do not raise it past what a rotation can bear.
- A token whose algorithm is refused (`none`, an HMAC, one off the allow-list) never fetches. Nor does a token with no
  `kid` when two keys could verify it: that is refused, not unknown.
- A `kid` the refetch did not bring stays unknown. It never falls back to another key.
- Keys the refetch adds void nothing. Keys it removes or replaces void the flows in flight and raise the trust version,
  including the sign-in that asked, so that person starts again.

Each refetch reports `JwksRefreshed` or `JwksRefreshFailed` (see [Events](events.md)) and is logged by its outcome, its
reason and the fetch's status alone.

## Risks

- **The document is trusted once saved.** Discovery proves the document came from the issuer's host over verified TLS,
  and nothing more. A compromised issuer host can point a refresh at new endpoints. If that is outside what you accept,
  leave `metadata_refresh` off and enter the endpoints by hand: refetches then only ever touch the keys, from the saved
  `jwks_uri`.
- **A refresh can move the JWKS and the token endpoint.** It voids what is in flight and reports `ConnectionUpdated`
  naming them. Alert on that event, since an endpoint move is rare and worth a look.
- **Sign-ins fail when the document does.** A provider serving a bad document does not change anything stored, but after
  30 days of failures sign-ins stop. Watch `MetadataRefreshFailed` well before then.
- **A key rotation voids flows.** A provider dropping or replacing a key voids what is in flight through the connection.
  People in the middle of signing in start again; nothing else is lost.
- **A narrow allow-list can refuse a good key.** A provider moving to an algorithm off the list keeps working only until
  it stops signing with the old one. The refresh never widens the list for you.
