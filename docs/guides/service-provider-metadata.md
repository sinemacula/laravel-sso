# Service provider metadata

Before a connection can be used, an administrator registers your service at the organisation's identity provider. For
a SAML connection that is your service provider metadata (SAML 2.0 Metadata): the entity id, where assertions are
posted, your signing and encryption certificates, the NameID format, and whether requests are signed and assertions
must be. Most identity providers take it as a URL they fetch, or as a file uploaded once.

`SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions` answers it for a tenant's connection:

```php
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;

$description = app(ServiceProviderDescriptions::class)->describe($tenantId, $connectionId);

if ($description->isAvailable()) {
    $description->contentType; // 'application/samlmetadata+xml'
    $description->body;        // the metadata XML
} else {
    $description->reason;      // FailureReason::CONNECTION_UNAVAILABLE or PROTOCOL_UNAVAILABLE
}
```

The helper is not SAML-specific: it asks the connection's protocol driver, so an OIDC connection answers what its
driver describes (the callback URL and, with `private_key_jwt`, the public JWKS, as `application/json`), and a driver
your application registers answers its own.

## Serving the metadata endpoint

The package builds the metadata URL, and the entity id, from `sso.endpoints.base_url` and
`sso.endpoints.paths.metadata` (see [Configuration](configuration.md)). Your application owns the route: register it
at the same path, so the URL the metadata names is the URL that serves it.

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;

Route::get(config('sso.endpoints.paths.metadata'), function (
    Request $request,
    string $connection,
    ServiceProviderDescriptions $descriptions,
) {
    // However your application resolves the tenant it serves: the host, a
    // route parameter, or a lookup of the connection id in your own records.
    $tenantId = (string) $request->attributes->get('tenant_id');

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

## Refusals

| Reason                   | When                                                                           |
|--------------------------|--------------------------------------------------------------------------------|
| `connection_unavailable` | The tenant has no connection with the id: unknown, or another tenant's         |
| `protocol_unavailable`   | No driver is registered under the connection's protocol, or its feature is off |

A disabled or incomplete connection is not refused. An empty tenant id, or one longer than 255 bytes, is an
`InvalidArgumentException`, as every helper that takes a tenant throws; so is an endpoint configuration that cannot
build a valid URL, which the boot check reports first, and an entity id longer than the 1,024 characters SAML allows.

Describing a connection changes nothing: it asks for no fresh authentication (see [Fresh authentication](freshness.md)),
writes nothing and reports no event.
