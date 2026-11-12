# SAML Requests

## Purpose

This note records how the SAML driver starts an SP-initiated sign-in (SSO-5.3, SSO-5.10): the `AuthnRequest` it writes,
the HTTP-Redirect and HTTP-POST bindings it sends it by (SAML 2.0 Bindings §3.4 and §3.5), how it is signed, what
`RelayState` carries, and how a `reauthenticate` forces fresh authentication. How the start is stored and reported is
in `authorization-requests.md`; how the response is correlated with the request is in `saml-responses.md`; the
adapter the request is written through is in `saml-adapter.md`.

## Invariants

### The request

- `Protocols\Saml2\AuthnRequests::start()` answers the driver's `Start`: `Start::navigate($navigation, $id)` with the
  request's `ID`, which the authorisation request stores as `saml_request_id`, unique per connection, for the
  response's `InResponseTo`; or `Start::refused(connection_unavailable)`.
- `ID` is `_` followed by 32 bytes of the system's CSPRNG as lower-case hex (65 bytes, within
  `Correlation::MAX_REQUEST_ID_LENGTH`), fresh for every start, so two starts never share one.
- `Version` is `2.0`. `IssueInstant` is the package's clock (`Contracts\Clock`) in UTC, to the second.
- `Issuer` is the service provider entity id and `AssertionConsumerServiceURL` the connection's assertion consumer
  service, both from `Contracts\EndpointResolver`, never from the request (SSO-5.5). `ProtocolBinding` is HTTP-POST:
  responses are accepted at the assertion consumer service by HTTP-POST only, and the artifact binding is not
  supported.
- `Destination` is the connection's single sign-on URL (`sso_url`), exactly as configured.
- `NameIDPolicy` carries the connection's NameID format (`persistent`, `email` or `unspecified`, as its URI) with
  `AllowCreate="true"`. The transient format is never requested: the settings refuse it.
- `ForceAuthn="true"` when the connection's `force_authn` is on, and always for the `reauthenticate` purpose
  (SSO-5.10); otherwise the attribute is absent. The response's `AuthnInstant` is then held to the request's creation
  by the response validation.
- `RequestedAuthnContext` is present only when the connection lists `requested_authn_context` classes: each as an
  `AuthnContextClassRef`, in the order listed, with `Comparison="exact"`. The response's class is checked against the
  same list.

### RelayState

- `RelayState` is the flow's protocol state (`StartRequest::$state`, 43 base64url characters), never the public
  reference, a verifier or a URL (SSO-5.2). A response is correlated by the digest of its `RelayState` against the
  stored state digest, and its `InResponseTo` against `saml_request_id`; they must name the same request.
- It is at most 80 bytes (SSO-5.3). A longer state is application code's mistake, a `LogicException` naming the limit,
  never the value.

### Bindings

- HTTP-Redirect: the XML (no XML declaration, no enveloped signature) is deflated raw (RFC 1951, level 9), base64
  encoded, and sent in the query string as `SAMLRequest`, then `RelayState`, then, when signed, `SigAlg` and
  `Signature`, in exactly that order. Each value is percent-encoded per RFC 3986 (`rawurlencode()`). The navigation is
  a redirect to the single sign-on URL with the query appended after `?`, or after `&` when the URL already has a
  query, or directly when the URL ends with `?` or `&`.
- HTTP-POST: the XML, signed when the connection signs its requests, base64 encoded as `SAMLRequest`, with
  `RelayState`. The navigation is a form posted to the single sign-on URL (`Navigation::post()`).
- `Protocols\Saml2\Messages\OutgoingRequest` carries the `ID`, the binding and the fields in sending order. The fields
  live in a `\SensitiveParameterValue`: a dump and `json_encode()` show their names with `[redacted]` values, and the
  value refuses to be serialised or unserialised.

### Signing

- A request is signed only when the connection's `sign_authn_requests` is on, with its current `sp_signing` key
  (`Keys\KeyRing::current()`, then `privateKey()`, a `Secrets\Secret`) and the first algorithm of its
  `signature_algorithms` (RSA-SHA256, RSA-SHA384 or RSA-SHA512).
- HTTP-Redirect: the signature is over exactly the bytes `SAMLRequest=...&RelayState=...&SigAlg=...` as they appear in
  the query, and is sent as `Signature`, base64 encoded. The XML is not signed.
- HTTP-POST: an enveloped signature placed after `Issuer`, referencing the request's `ID`, with exclusive
  canonicalisation (without comments), the enveloped-signature and exclusive canonicalisation transforms, and the
  digest that belongs to the signature algorithm (SHA-256, SHA-384 or SHA-512). It carries no `KeyInfo`: the identity
  provider verifies with the certificate the service provider metadata publishes.
- The private key is revealed only inside `Library\AuthnRequestWriter`, for the call that signs. It, the `RelayState`,
  the encoded message and the signature are never logged, reported, or put in an exception message.

### The adapter

- `Library\AuthnRequestWriter` is the adapter's entry for outgoing requests: the one class this flow calls
  `simplesamlphp/saml2` and `simplesamlphp/xml-security` through, inside the adapter's namespace and under the same
  architecture test. It builds the request from the library's `AuthnRequest`, `Issuer`, `NameIDPolicy` and
  `RequestedAuthnContext`, and signs with the library's `SignatureAlgorithmFactory` and `PrivateKey`.
- saml2 v6 writes no `ForceAuthn` (it compares the typed value with `true`), so the request is written by a subclass
  that adds the attribute before anything is signed, and names its element without reading its class name.
- Nothing in the driver keeps anything between calls (SSO-11.2).

## Success Path

1. The application starts a `sign_in` through a usable SAML connection; the start service generates the protocol state
   and asks the driver, outside any transaction.
2. The driver checks the metadata expiry (`metadata-refresh.md`), then `AuthnRequests` writes the request: a fresh
   `ID`, the issue instant, the endpoints, the connection's options, `ForceAuthn` when asked, the state as `RelayState`,
   and the signing key when the connection signs.
3. The start answers `Start::navigate()` with the redirect or the post and the `ID`; the start service stores the
   request with `saml_request_id` under the connection's lock and reports `AuthorizationRequestStarted`.
4. The identity provider answers at the assertion consumer service by HTTP-POST with `InResponseTo` equal to the `ID`
   and the same `RelayState`.

## Failure / Edge Cases

- A connection that signs its requests with no current `sp_signing` key, or with no single sign-on URL, is refused with
  `connection_unavailable`. A complete connection has both (`Saml2Driver::isComplete()`), so this is a backstop.
- Metadata that has expired is refused with `metadata_expired` by the driver before a request is written; the start
  reports one `FlowFailed` and stores nothing.
- A `RelayState` over 80 bytes is a `LogicException`.
- A connection that allows no signature algorithm, a key the library cannot read, or a value the library refuses (a
  requested context class that is not a URI) is one `LogicException` with the package's own message and no previous
  exception, so no key or message reaches a log through it.
- A duplicate `saml_request_id` for the connection is refused by the unique index, as a database error.

## Implementation Anchors

- `src/Protocols/Saml2/AuthnRequests.php`
- `src/Protocols/Saml2/Library/AuthnRequestWriter.php`
- `src/Protocols/Saml2/Messages/OutgoingRequest.php`
- `src/Protocols/Saml2/Saml2Driver.php` (`start()`)
- `src/Flows/AuthorizationRequestService.php` (stores `saml_request_id`)

## Authoritative Tests

- `tests/Feature/Protocols/Saml2/AuthnRequestsTest.php`
- `tests/Feature/Protocols/Saml2/Library/AuthnRequestWriterTest.php`
- `tests/Feature/Flows/SamlStartTest.php`
- `tests/Unit/Architecture/SamlLibraryBoundaryTest.php`

## Change Triggers

- A saml2 release that writes `ForceAuthn` itself: the subclass can go.
- The PHP floor reaches 8.5 and saml2 v7: the writer is rewritten with the adapter.
- A new binding, a requested `IsPassive`, `Scoping` or `Subject`, or a `KeyInfo` in the signature.
