# Service provider metadata

Before a connection can be used, an administrator registers your service at the organisation's identity provider. For
a SAML connection that is your service provider metadata (SAML 2.0 Metadata): the entity id, where assertions are
posted, your signing and encryption certificates, the NameID format, and whether requests are signed and assertions
must be. Most identity providers take it as a URL they fetch, or as a file uploaded once.

`SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions` answers it for a tenant's connection:

<!-- snippet: tests/Integration/Examples/ServiceProviderMetadata/describe.php#service-provider-describe -->
```php
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;

$description = app(ServiceProviderDescriptions::class)->describe($tenantId, $connectionId);

if ($description->isAvailable()) {
    $contentType = $description->contentType; // 'application/samlmetadata+xml'
    $metadata    = $description->body;        // the metadata XML
} else {
    $reason = $description->reason; // FailureReason::CONNECTION_UNAVAILABLE or PROTOCOL_UNAVAILABLE
}
```

The helper is not SAML-specific: it asks the connection's protocol driver, so an OIDC connection answers what its
driver describes (the callback URL and, with `private_key_jwt`, the public JWKS, as `application/json`: see
[What an OIDC connection registers](#what-an-oidc-connection-registers)), and a driver your application registers
answers its own.

## Serving the metadata endpoint

The package builds the metadata URL, and the entity id, from `sso.endpoints.base_url` and
`sso.endpoints.paths.metadata` (see [Configuration](configuration.md)). Your application owns the route: register it
at the same path, so the URL the metadata names is the URL that serves it.

<!-- snippet: tests/Integration/Examples/ServiceProviderMetadata/metadata-route.php#service-provider-metadata-route -->
```php
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;

Route::get(config('sso.endpoints.paths.metadata'), static function (
    Request $request,
    string $connection,
    ServiceProviderDescriptions $descriptions,
): Response {
    // However your application resolves the tenant it serves: the host, a route
    // parameter, or a lookup of the connection id in your own records.
    $tenantId = $request->attributes->getString('tenant_id');

    $description = $descriptions->describe($tenantId, $connection);

    abort_unless($description->isAvailable(), 404);

    return response($description->body, 200, [
        'Content-Type'  => $description->contentType,
        'Cache-Control' => 'public, max-age=3600',
    ]);
})->name('sso.metadata');
```

The default path is `/auth/sso/connections/{connection}/metadata`, so `{connection}` arrives as the route's
`$connection`. The identity provider fetches the URL without signing in, so the route takes no authentication; the
metadata holds nothing secret. Answer both refusals with the same `404`: a connection the tenant does not have, unknown
or another tenant's, is refused exactly as an unknown one, and your response should not tell them apart either.

Some identity providers expect `text/xml` or `application/xml` rather than `application/samlmetadata+xml`; send the
type yours needs. Keep any cache lifetime well inside your key overlap (`keys.overlap_seconds`), so an identity provider
that refetches sees a new key before it is used.

## What the SAML metadata holds

One unsigned `md:EntityDescriptor` for the connection, with one `md:SPSSODescriptor`:

| Element or attribute             | Value                                                                                   |
|----------------------------------|-----------------------------------------------------------------------------------------|
| `entityID`                       | The connection's entity id: its metadata URL, with the default resolver                 |
| `protocolSupportEnumeration`     | `urn:oasis:names:tc:SAML:2.0:protocol`                                                  |
| `AuthnRequestsSigned`            | The connection's `sign_authn_requests` (`false` by default)                             |
| `WantAssertionsSigned`           | The connection's `want_assertions_signed` (`true` by default)                           |
| `KeyDescriptor use="signing"`    | The certificate of each published signing key: the current one, then the next one       |
| `KeyDescriptor use="encryption"` | The certificate of each published encryption key: the current one, then the next one    |
| `EncryptionMethod`               | On each encryption key: the data encryption algorithms allowed, then the key transports |
| `NameIDFormat`                   | The connection's `name_id_format` (`persistent` by default)                             |
| `AssertionConsumerService`       | HTTP-POST, at the connection's assertion consumer service URL, `index="0"`, the default |

With the default `encryption_algorithms`, each encryption key lists AES-128-GCM, AES-192-GCM, RSA-OAEP
(`http://www.w3.org/2009/xmlenc11#rsa-oaep`) and RSA-OAEP with MGF1 (`http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p`).
AES-CBC is listed only when you add it to the connection's `encryption_algorithms`. AES-256-GCM is never listed: the
SAML library the package uses cannot decrypt it until its next major version. RSA 1.5 is never accepted or listed.

The metadata is the service provider side only, so a connection is described before its identity provider settings are
given, and while it is disabled: register it at the identity provider first, then fill in the provider's settings and
enable it. A connection with no keys yet has no `KeyDescriptor`; add its keys (see
[Keys and certificates](keys.md)) before registering it if it signs its requests or requires encrypted assertions.

It never holds a private key or any secret, and it has no `ID`, `validUntil` or `cacheDuration`, so the same connection
always gives the same bytes: you can compare what you served before with what you serve now to see whether it changed.

## Rotating keys

The metadata follows the key ring (see [Keys and certificates](keys.md)):

1. While a key is only `current`, its certificate is the only one of its use.
2. Add the next key with `KeyService::addNext()`: the metadata now lists the current certificate, then the next one.
   Have the identity provider refetch (or reupload) the metadata, so it knows the new key before it is used.
3. Make the next key current with `KeyService::makeCurrent()`: the metadata lists only the new certificate. The
   replaced key is `retiring` and still decrypts until the overlap ends, but is no longer advertised.
4. Retire the old key with `KeyService::retire()`: the metadata is unchanged.

## What an OIDC connection registers

An OIDC connection answers `application/json`: client metadata in the shape of RFC 7591, holding what an administrator
enters at the OpenID provider when creating the client. The package does not register anything itself, and the provider
gives you the client id and any client secret to save on the connection (see
[Managing connections](managing-connections.md)).

With `client_secret_basic` or `client_secret_post`:

```json
{
    "redirect_uris": ["https://api.example.com/auth/sso/connections/01jc3yq6v8h2m9t4n7r5w1k0xs/callback"],
    "response_types": ["code"],
    "grant_types": ["authorization_code"],
    "token_endpoint_auth_method": "client_secret_basic"
}
```

With `private_key_jwt`, it adds the signing algorithm and the URL of the connection's public keys, which your
application serves:

```json
{
    "redirect_uris": ["https://api.example.com/auth/sso/connections/01jc3yq6v8h2m9t4n7r5w1k0xs/callback"],
    "response_types": ["code"],
    "grant_types": ["authorization_code"],
    "token_endpoint_auth_method": "private_key_jwt",
    "token_endpoint_auth_signing_alg": "ES256",
    "jwks_uri": "https://api.example.com/auth/sso/connections/01jc3yq6v8h2m9t4n7r5w1k0xs/jwks"
}
```

A provider that requires uploaded keys is given `describeWithInlineKeys($tenantId, $connectionId)` instead, the same
document with the keys in it, and never both in one document:

```json
{
    "redirect_uris": ["https://api.example.com/auth/sso/connections/01jc3yq6v8h2m9t4n7r5w1k0xs/callback"],
    "response_types": ["code"],
    "grant_types": ["authorization_code"],
    "token_endpoint_auth_method": "private_key_jwt",
    "token_endpoint_auth_signing_alg": "ES256",
    "jwks": {
        "keys": [
            {
                "crv": "P-256",
                "kty": "EC",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "kid": "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s",
                "use": "sig",
                "alg": "ES256"
            }
        ]
    }
}
```

The body is compact JSON, with its members in this order; it is shown indented here.

| Member                            | Value                                                                               |
|-----------------------------------|-------------------------------------------------------------------------------------|
| `redirect_uris`                   | The connection's callback, as your endpoint resolver builds it; register it exactly |
| `response_types`                  | `code`: the only flow the package runs                                              |
| `grant_types`                     | `authorization_code`                                                                |
| `token_endpoint_auth_method`      | The connection's `client_authentication` (`client_secret_basic` by default)         |
| `token_endpoint_auth_signing_alg` | `private_key_jwt` only: the pinned algorithm, or that of the key that signs         |
| `jwks_uri`                        | `private_key_jwt` only, by default: where the provider fetches the public keys      |
| `jwks`                            | The inline export only: the public JWK of each published key, current and then next |

An RSA key signs with `PS256` (or `RS256`, when the connection's
[`client_assertion_algorithm`](oidc-connections.md#the-client-assertion-algorithm) pins it) and a P-256 key with
`ES256`: the assertion's header, each key's `alg` and the description always agree. Each key's `kid` is the RFC 7638
thumbprint of its public half, the one its client assertions name, so it stays the same for as long as the key does,
whatever the algorithm, and the provider can pick the right key by it.

The callback comes from the endpoint resolver, never from the request (see [Configuration](configuration.md)), so a
forged `Host` header cannot move it. It is the URL your application's callback route must serve (see
[The OIDC callback](oidc-callback.md)), and the provider compares it exactly.

### Serving the public keys

The `jwks_uri` is stable for the life of the connection, and built by your endpoint resolver from
`sso.endpoints.paths.jwks`. The package adds no route: serve it yourself, from a route that needs no authentication,
since it is the provider that fetches it and it holds public keys alone. The package gives you the body:

<!-- snippet: tests/Integration/Examples/ServiceProviderMetadata/jwks-route.php#service-provider-jwks-route -->
```php
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;

Route::get(config('sso.endpoints.paths.jwks'), static function (string $connection, ServiceProviderDescriptions $descriptions): Response {
    $keys = $descriptions->publicKeys($connection);

    abort_unless($keys->isAvailable(), 404);

    return response($keys->body, 200, [
        'Content-Type'  => $keys->contentType,
        'Cache-Control' => 'public, max-age=300',
    ]);
})->name('sso.jwks');
```

`publicKeys()` takes the connection's id alone, whichever tenant it belongs to, since the provider names no tenant. Keep
any cache lifetime short: a next key has to reach the provider before it is made current.

Prefer the URL where the provider can fetch one: a rotation then needs nothing from you at the provider. With the inline
export, you must **register again** every time a next key is added or made current, or the provider stops accepting the
connection's assertions. A provider that takes a file or a form field takes the inline `jwks` member, and most ask for
only some of these values: enter what yours asks for.

### What can be described

The description is the relying party's side only, so a connection is described before the provider's settings are
given, and while it is disabled. What the connection does hold must be valid, though: a client authentication the
package does not support, and a `client_assertion_algorithm` its keys cannot sign under, are `settings_invalid`.
`private_key_jwt` with no key has nothing to register, so it is `connection_unavailable` until you add one with
`KeyService::addNext()` (see [Keys and certificates](keys.md)).

It never holds a client secret, a private key or the client id, and has no timestamp, so the same connection always
gives the same bytes.

## Rotating an OIDC connection's keys

The public keys follow the key ring, as SAML metadata does. Only `private_key_jwt` connections have keys to rotate:

1. While a key is only `current`, it is the only one listed.
2. Add the next key with `KeyService::addNext($tenantId, $connectionId, KeyUse::CLIENT_ASSERTION)`: the JWKS now lists
   the current key, then the next one. The current key still signs. Let the provider refetch the URL or, with the inline
   export, register again, so the provider knows the new key before it is used.
3. Make the next key current with `KeyService::makeCurrent()`: the JWKS lists only the new key, and every client
   assertion is signed with it from that moment. The replaced key is `retiring`, and is no longer listed: a retiring
   key decrypts for a SAML connection during its overlap, but signs nothing, so it has no further use here. Remove it
   from the provider if your provider keeps a list.
4. Retire the old key with `KeyService::retire()`: the JWKS is unchanged.

Do not make the next key current until the provider holds it: its client assertions are refused with `invalid_client`
from that moment until it does, and the sign-in fails.

`addNext()` makes an RSA key unless you give another type. A rotation that changes the type also changes
`token_endpoint_auth_signing_alg` when the new key is made current. A provider that enforces that value refuses the new
key's assertions until its registration names the new algorithm, so update it as you make the key current, or keep to
one type.

## Refusals

| Reason                   | When                                                                             |
|--------------------------|----------------------------------------------------------------------------------|
| `connection_unavailable` | The tenant has no connection with the id: unknown, or another tenant's           |
| `connection_unavailable` | An OIDC connection using `private_key_jwt` has no current or next key            |
| `connection_unavailable` | The public keys of a client secret connection, which has none to serve           |
| `connection_unavailable` | The public keys or the inline export of another protocol                         |
| `settings_invalid`       | An unsupported client authentication, or an algorithm its keys cannot sign under |
| `protocol_unavailable`   | No driver is registered under the connection's protocol, or its feature is off   |

The inline export of a client secret connection is its plain client metadata: it has no keys to put in the document, so
it is the same document `describe()` gives. A disabled or incomplete connection is not refused. An empty tenant id, or
one longer than 255 bytes, is an `InvalidArgumentException`, as every helper that takes a tenant throws; so is an
endpoint configuration that cannot build a valid URL, which the boot check reports first, an entity id longer than the
1,024 characters SAML allows, and a published client assertion key the package would not sign with (it generates only
keys it would).

Describing a connection changes nothing: it asks for no fresh authentication (see [Fresh authentication](freshness.md)),
writes nothing and reports no event.
