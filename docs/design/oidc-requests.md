# OIDC Requests

## Purpose

This note records how the OIDC driver starts an authorisation code flow (SSO-5.4, SSO-5.10, SSO-2.4, SSO-7.1): the URL
it sends the browser to, the order and encoding of its parameters, what an extra parameter or an authorisation endpoint
with a query of its own may and may not do, and what the request keeps. How the start is stored and reported is in
`authorization-requests.md`; how the driver is put together is in `oidc-driver.md`; how the callback is checked against
what the request kept is in `oidc-callback.md`.

## Invariants

### The start

- `Protocols\Oidc\AuthorizationRequests::start()` answers the driver's `Start`:
  `Start::navigate(Navigation::redirect($url), null, $issuer, $returnsIss)`, or `Start::refused(connection_unavailable)`
  when the authorisation endpoint cannot carry the request. It never answers a SAML request id.
- The driver checks the metadata expiry before it asks (`metadata-refresh.md`), and the start pipeline asks only a
  usable, so complete, connection (`OidcDriver::isComplete()`), so a start reads a valid issuer, endpoints and client
  id. Started anyway on an incomplete connection, it is a `LogicException` naming the setting.
- A `StartRequest` with no nonce or no PKCE verifier is a `LogicException`: the start pipeline's bug, never a request
  sent without them.
- A start makes no network call, logs nothing and reports nothing. It holds the endpoint resolver alone, and no
  exception names a value.

### The URL

`AuthorizationUrl::build()` appends these parameters, in exactly this order, to the authorisation endpoint:

| Parameter                 | Value                                                                                   |
|---------------------------|-----------------------------------------------------------------------------------------|
| `response_type`           | `code`, the only response type (no implicit or hybrid flow)                             |
| `client_id`               | The connection's client id                                                              |
| `redirect_uri`            | The connection's callback from `Contracts\EndpointResolver`, exactly (SSO-5.5)          |
| `scope`                   | The connection's scopes joined by single spaces, in stored order                        |
| `state`                   | `StartRequest::$state`, 43 random base64url characters, never the public reference      |
| `nonce`                   | `StartRequest::$nonce`, 43 random base64url characters                                  |
| `code_challenge`          | The S256 challenge of `StartRequest::$codeVerifier`, as `Flows\ProtocolState` computes  |
| `code_challenge_method`   | `S256`                                                                                  |
| `max_age`                 | `0` for a `reauthenticate`, else the connection's `max_age` when it has one             |
| `prompt`                  | `login` for a `reauthenticate`                                                          |
| the extra parameters      | The connection's `extra_parameters`, in stored order                                    |

- `max_age` is sent as configured, `0` included: a `sign_in` through a connection whose `max_age` is `0` sends `0`, and
  one with none sends nothing. For a `reauthenticate` it is always `0`, whatever is configured.
- No `response_mode` is sent: the code flow's default query mode is the only one the callback accepts. `request` and
  `request_uri` are never sent.
- The PKCE verifier never leaves the API (SSO-5.2); only its challenge is sent. It is independent of the client's own
  verifier, whose challenge the request keeps for the handoff (`authorization-requests.md`).
- The query is encoded per RFC 3986 (`http_build_query()` with `PHP_QUERY_RFC3986`): a space is `%20`, never `+`.

### Extra parameters

- The settings allow only the listed names and refuse a name the flow controls, in any case (`OidcSettings`), and only
  a connection whose settings are valid is used.
- `AuthorizationUrl` checks again: an extra parameter is left out when its name, in any case, is in
  `OidcSettings::RESERVED_PARAMETERS` or is one the request already sets (`prompt` and `max_age` for a `reauthenticate`,
  `max_age` when the connection configures one), or when it is not a string under a name. An extra parameter therefore
  never sets, overrides or repeats one the flow controls.
- A `reauthenticate` leaves an extra `prompt` out: `prompt=login` wins (SSO-5.10). Every other purpose sends it.

### An endpoint with a query

- The settings allow an authorisation endpoint to carry a query and refuse a fragment. Its query is kept as it is, and
  the request's is appended after `&`, or directly when the endpoint ends with `?` or `&`.
- When its own query names a parameter the request sets, or one the flow controls and never sets (`response_mode`,
  `request`, `request_uri`), compared after percent-decoding and in any case, there is no URL and the start is refused
  with `connection_unavailable`: nothing is overridden or sent twice. An endpoint with a fragment is refused the same
  way, as a backstop to the settings.

### What the request keeps

- `Start` carries the connection's issuer, exactly as configured and never normalised, and `returns_iss`: whether the
  provider must return the RFC 9207 `iss` (SSO-7.1). An administrator sets it, or an import or a refresh does when the
  discovery document advertises `authorization_response_iss_parameter_supported` (`oidc-discovery.md`).
- The start pipeline stores them as `expected_issuer` and `issuer_required`, beside `state_digest` and `nonce_digest`
  (the lower-case hex SHA-256 of each, never the value), `code_verifier` (the PKCE verifier, encrypted),
  `handoff_challenge`, and `trust_version`, the connection's as it read it before asking the driver
  (`authorization-requests.md`).
- The `Navigation` holds the URL in a `\SensitiveParameterValue`: every dump shows the endpoint and the parameters'
  names with `[redacted]` values, so no `state`, `nonce` or `code_challenge` reaches a log through it.

### Trust changes

- The driver runs outside any transaction. The start pipeline then locks the connection's row and stores nothing when
  its switch, settings, secrets or trust version changed since it read them, refusing with `connection_unavailable`.
  A stored request raises the connection's flows version under that lock, so a change that committed after it voids
  it, and a PostgreSQL `REPEATABLE READ` change whose snapshot predates it fails to serialise rather than miss it
  (`Connections\InFlightVoider`).
- An update of the client secret or the JWKS URL is such a change (`Enums\OidcSetting::freshness()`). No request
  survives one that committed.

## Success Path

1. The application starts a flow through a usable OIDC connection; the start service generates the protocol state and
   asks the driver, outside any transaction.
2. The driver checks the metadata expiry, then `AuthorizationRequests` reads the callback from the endpoint resolver and
   `AuthorizationUrl` builds the URL.
3. The start answers the redirect, the issuer and whether it must return `iss`; the start service stores the request
   under the connection's lock and reports `AuthorizationRequestStarted` after it commits.
4. The provider answers at the callback with `state`, the code and, when it returns it, `iss` (`oidc-callback.md`).

## Failure / Edge Cases

- A disabled or incomplete connection, one with no client secret, or `private_key_jwt` with no current key: the start
  pipeline refuses `connection_unavailable` and the driver is never asked.
- A discovery document or a JWKS past the stale limit: the driver refuses `metadata_expired`.
- An authorisation endpoint whose query names a parameter the request sets: `connection_unavailable`.
- A trust change committed while the driver ran: `connection_unavailable`, nothing stored.
- Every refusal stores nothing and reports exactly one `FlowFailed(authorization_request, reason)`.
- A `StartRequest` with no nonce or PKCE verifier, an incomplete connection asked anyway, and an endpoint resolver that
  throws: the exception propagates (SSO-11.4).

## Implementation Anchors

- `src/Protocols/Oidc/AuthorizationRequests.php`, `AuthorizationUrl.php`.
- `src/Protocols/Oidc/OidcDriver.php` (`start()`), `OidcOptions.php`, `OidcSettings.php` (`RESERVED_PARAMETERS`).
- `src/Flows/AuthorizationRequestService.php`, `ProtocolState.php`.

## Authoritative Tests

- `tests/Unit/Protocols/Oidc/AuthorizationUrlTest.php`
- `tests/Feature/Protocols/Oidc/AuthorizationRequestsTest.php`
- `tests/Feature/Flows/OidcStartTest.php`
- `tests/Integration/Flows/OidcStartRaceTest.php`
- `tests/Integration/Connections/ConnectionUsabilityTest.php`

## Change Triggers

- A new parameter the flow sends, or a response mode other than the default.
- A new extra parameter on the allow-list, or a change to what the flow reserves.
- A change to what the request keeps, or to how a start is stored.
- Signed or encrypted request objects (`request`, `request_uri`), or pushed authorisation requests.
