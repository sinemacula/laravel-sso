# OIDC Relying Party Description

## Purpose

This note records what the `oidc` driver answers when an administrator needs to register a connection at its OpenID
provider (SSO-5.9): the callback URL and, with `private_key_jwt`, the public JWKS of the connection's current and next
keys, as RFC 7591 client metadata. It covers the document's exact shape, where each value comes from, how a key
rotation shows in it, and why it can hold no secret. The public helper around it is in `service-provider-metadata.md`;
the driver as a whole is in `oidc-driver.md`.

## Invariants

- `Protocols\Oidc\RelyingPartyDescription::describe(connection, options)` answers
  `ServiceProviderDescription::document('application/json', body)`, or `unavailable(connection_unavailable)`.
  `OidcDriver::describe()` calls it with `OidcOptions` read afresh, and `Connections\ServiceProviderDescriptions` is
  the way in for an application.
- The body is one JSON object with these members, in this order, so the same state always gives the same bytes:
  - `redirect_uris`: one URL, the connection's callback as `Contracts\EndpointResolver` builds it (SSO-5.5), the same
    value the start sends and the token request repeats as `redirect_uri`. Nothing is read from the request;
  - `response_types`: `["code"]`, and `grant_types`: `["authorization_code"]`, the only flow the package runs (SSO-5.4);
  - `token_endpoint_auth_method`: `OidcOptions::clientAuthentication()`, default applied;
  - with `private_key_jwt` only, `token_endpoint_auth_signing_alg` and `jwks` (`{"keys": [...]}`).
- `jwks` holds `Jose\ClientKey::publicJwk()` of each `Keys\KeyRing::published()` key of the use `client_assertion`: the
  current key, then the next one (SSO-2.7). A `retiring` key is never published: a client assertion is only ever signed
  by the current key, so a replaced key has no further use at the provider.
- The ring is read once per call, so the keys and the algorithm named are of one state of it.
- Each key's `kid` is the RFC 7638 thumbprint of its public half, which is also the `kid` header of every client
  assertion its private half signs (`JoseAdapter::signClientAssertion()`). Each key also carries `use` `sig`, and `alg`
  by its type: `PS256` for RSA and `ES256` for P-256.
- `token_endpoint_auth_signing_alg` is the algorithm of the first key published: the current key's, which is what signs.
  The key service never leaves a next key without a current one, so a next key alone (a row stored by other means)
  names its own algorithm, since it is what would sign once made current.
- Nothing secret is reachable. The description reads only the callback, the method and each key's public half
  (`KeySummary::$key`, a `Secrets\MaskedKey`, which refuses a private key); it never calls `KeyRing::privateKey()` or
  `ConnectionSecrets`, and `ClientKey::publicJwk()` reads a public PEM alone. It holds no private member (`d`, `p`, `q`,
  `dp`, `dq`, `qi`), no client secret, no client id and no key id but the thumbprint: neither the row's id nor the
  fingerprint.
- Any connection whose callback can be built is described, enabled or not, complete or not, since an administrator
  registers it first (SSO-2.1). Being described says nothing about being usable.
- Describing changes nothing: it asks for no fresh authentication, writes nothing and reports no event. Every value is
  read afresh and nothing is kept between calls (SSO-11.2).
- The JSON is encoded with `JSON_UNESCAPED_SLASHES` and `JSON_THROW_ON_ERROR`, so a URL reads as it is registered and a
  value JSON cannot hold is an error, never a partial document.

## Success Path

- A client secret connection answers the callback, the code flow and its method.
- A `private_key_jwt` connection answers those, then its signing algorithm and its JWKS. The administrator registers
  them, and the provider verifies each client assertion with the key whose `kid` it names.
- During a rotation (`keys.md`):
  1. `KeyService::addNext()` adds the next key, and the description lists the current key, then the next. The
     administrator registers the new JWKS, or the provider refetches it, while the current key still signs.
  2. `KeyService::makeCurrent()` makes it current, and the description lists it alone. Client assertions are signed with
     it from that moment. The replaced key is `retiring`, and is gone from the description.
  3. `KeyService::retire()` removes the old key, and the description does not change.

## Failure / Edge Cases

- `private_key_jwt` with neither a current nor a next key of the connection's own has nothing to register:
  `connection_unavailable`. A `retiring` key alone, a key of another use and another connection's key do not count.
  A client secret connection needs no key, and lists none even if it holds one.
- An endpoint configuration that cannot build the callback is the endpoint resolver's `InvalidArgumentException`, which
  the boot check reports first. It is built before the keys are read, so the answer does not depend on them.
- A published key `ClientKey` does not admit (any other curve, or an RSA key under 2048 bits) cannot sign a client
  assertion either, and fails closed with its `InvalidArgumentException`, which names nothing of the key. It is not
  left out: a description that hides it would not match what the token request does. The package generates only keys it
  admits.
- A method stored past the settings' validation is answered as stored, with no keys, since the description is
  available for any connection whose callback can be built; such a connection has no credential and never completes
  (`TokenExchange`). A value JSON cannot hold is a `JsonException`.
- When a rotation changes the key's type, the two keys' `alg` differ and the signing algorithm is the current key's
  until `makeCurrent()`. RFC 7591 allows one `token_endpoint_auth_signing_alg`, so a provider that enforces it has to be
  updated at that moment; the guide says so.
- A database error propagates (SSO-11.4).

## Implementation Anchors

- `src/Protocols/Oidc/RelyingPartyDescription.php`: the document.
- `src/Protocols/Oidc/OidcDriver.php`: `describe()`, which reads the options and delegates.
- `src/Protocols/Oidc/Jose/ClientKey.php`: the public JWK, its `kid` and its algorithm.
- `src/Protocols/Oidc/Jose/JoseAdapter.php`: `signClientAssertion()`, which signs under the same `kid`.
- `src/Keys/KeyRing.php`: `published()`, the current key and then the next one.
- `src/Contracts/EndpointResolver.php`, `src/Endpoints/ConfiguredEndpointResolver.php`: the callback.
- `src/Connections/ServiceProviderDescriptions.php`: the public helper.

## Authoritative Tests

- `tests/Feature/Protocols/Oidc/RelyingPartyDescriptionTest.php`: the exact JSON for each client authentication, with
  RFC 7638's example key under the thumbprint the RFC gives; current then next, whichever was stored first; a rotation
  by the key service, the replaced key gone once retiring and still gone once retired; `PS256` and `ES256`; the `kid`
  equal to the client assertion's header; no private member or secret in the body or any dump; the callback the
  resolver's, a bound resolver honoured and a forged request ignored; unavailable with no key; a key the package would
  not sign with refused; nothing asked, written or reported; and the fake provider accepting the package's client
  assertion with the published key, refusing it with any other, and accepting the next key once it is made current.
- `tests/Feature/Connections/OidcServiceProviderDescriptionsTest.php`: the same through the public helper: tenant
  scoping, an unknown connection answered identically, the feature off, a rotation, no secret.

## Change Triggers

- A new client authentication method, or a new key type or algorithm in `ClientKey`.
- A second callback, another response type or grant: each adds to the document and to the exact JSON its tests pin.
- A `jwks_uri` the package would publish in place of `jwks`, which would add an endpoint to `EndpointResolver`.
- Publishing a `retiring` key, should a client assertion ever be signed by one.
- The endpoint resolver contract or the key ring's `published()` order changes.
