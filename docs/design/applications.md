# Applications and Endpoints

## Purpose

This note records how the package knows the applications people sign into and the URLs it publishes for each
connection (SSO-5.5, SSO-5.1): the application registry, the one exact redirect URI of each application and the
contract that answers it, the contract that says whether an application allows sign-in through an external provider,
and the contract that builds a connection's assertion consumer service, OIDC callback, service provider entity id and
metadata URL. None of them reads anything from the request.

## Invariants

- Applications are configuration, never rows: `sso.applications.<name>`, a fixed set deployed with the code (the
  suite's own front ends). Each client's connections are rows, unlimited. A name is a lower-case letter, then up to 63
  lower-case letters, digits, `_` and `-`, with nothing after them (`Applications\Application::isName()`).
- `Applications\Application` is one application, built only by `fromSettings()`, which the boot check
  (`Config\Checks\ApplicationsCheck`) and the flows both use, so they judge a configuration the same way. It holds the
  one `redirectUri`, exactly as configured; `externalSignIn` (off unless set); the `delivery` of the handoff code
  (`Applications\Enums\HandoffDelivery`: `fragment`, the default, or `query`); `discoveryEnabled` and the
  `discoveryFallbackUrl`, required while discovery is offered and the `discovery` feature is on (or its switch is
  malformed), and checked whenever it is given; `unlinkedHandoffs` (off unless set); and `handoffTtlSeconds`, 1 to 300,
  60 by default. Any other setting is refused, naming the key and never the value.
- A redirect URI and a fallback URL are `Config\UrlSetting::redirect()` values: `https`, `http` on `127.0.0.1` or
  `[::1]`, or a private-use scheme with a dot that a native application registers (RFC 8252 section 7.1), with no user
  information, fragment, wildcard, whitespace or control character, at most 2048 bytes. They are used exactly as
  configured: the package appends the code or the failure code and the public reference (in the fragment or the query as
  the application's `delivery` says) and never a path, and it carries no return URL; the application keeps its own,
  keyed by its verifier (SSO-5.5, RFC 9700 section 2.1).
- `Applications\ApplicationRegistry` reads `sso.applications` on each call and finds an application only under exactly
  its name: an unknown name, a name of another form and a dotted path (`web.redirect_uri`) are all `null`, never another
  application or a setting. A registered application whose settings are malformed fails closed with the
  `InvalidArgumentException` of `fromSettings()`.
- `Contracts\ApplicationPolicy::externalSignIn(Application)` answers `Applications\Enums\ExternalSignIn` (`allowed`,
  `not_allowed`). The default, `Applications\ConfiguredApplicationPolicy`, answers the `external_sign_in` setting; under
  `laravel-iam` it is bound to AUTH-3.7's per-application method list. It is asked before a start and again before a
  handoff is issued; anything but `allowed` is `application_not_allowed`.
- `Contracts\RedirectUriResolver::redirectUri(Application, SsoConnection)` answers the exact URI for the application,
  through the connection the authorisation request names, read from storage. The default,
  `Applications\ConfiguredRedirectUriResolver`, answers the configured `redirect_uri` whatever the connection; an
  application binds its own to answer a per-client address without a schema change.
- `Applications\ApplicationGate` is the one way a flow reaches an application. `admit($name)` answers an
  `Applications\ApplicationAdmission`: `admitted` with the application, or `refused` with `application_not_allowed`
  whether the name is unknown or the policy does not allow it, so a refusal says nothing of which; the policy is never
  asked about a name no application is registered under. `redirectUri($application, $connection)` asks the resolver
  and checks the answer with `UrlSetting::redirect()`; an answer that is not an exact redirect URI is a misconfigured
  binding and fails closed with a `LogicException` naming the application, never the answer.
- `Contracts\EndpointResolver::endpoints(SsoConnection)` answers an `Endpoints\ConnectionEndpoints`: the
  `assertionConsumerService`, `callback`, `entityId` and `metadata` URLs. Each must be an absolute `https` URL, or
  `http` on a loopback address, with no user information, fragment or wildcard (`UrlSetting::web()`), or the value
  refuses to be built (`InvalidArgumentException`, naming the endpoint), so no resolver can publish or check an
  endpoint a response could be addressed to elsewhere.
- The default, `Endpoints\ConfiguredEndpointResolver`, builds each endpoint as `sso.endpoints.base_url` without its
  trailing slashes, then the endpoint's pattern from `sso.endpoints.paths` with `{connection}` replaced by the
  connection's id, percent-encoded; the entity id is the metadata URL. `Endpoints\EndpointSettings` reads the base URL
  (a web URL with no query, which may carry a path prefix) and the patterns (an absolute path of unreserved characters
  holding `{connection}` once, no other brace, no dot segment, nothing after it, and distinct from the others) on each
  call, the one way the resolver and the boot check (`Config\Checks\EndpointsCheck`) both read them. A connection with
  no id is refused. Nothing is built from the request's host, `X-Forwarded-*` headers or scheme.
- A completion is accepted only at the endpoint resolved for the connection its authorisation request names, SAML
  `Destination` and `Recipient` are compared with `assertionConsumerService` exactly, and the OIDC callback is sent as
  `redirect_uri` exactly.
- Every binding is a default, a singleton (the policy and the redirect resolver hold nothing) or scoped (the endpoint
  resolver reads configuration), so an application's or a sibling's earlier binding is kept, and nothing
  of one request outlives it (SSO-11.2).

## Success Path

1. The application registers `web` with its redirect URI and `external_sign_in` on, and sets
   `sso.endpoints.base_url`; the boot check passes `[endpoints]` and `[applications]`.
2. A start names `web`: `ApplicationGate::admit('web')` finds it and the policy allows it.
3. The driver builds its request with `EndpointResolver::endpoints($connection)` (the ACS URL, the callback, the entity
   id); metadata is published at the metadata URL.
4. The completion's redirect goes to `ApplicationGate::redirectUri($application, $connection)`, exactly.

## Failure / Edge Cases

- An unknown application, an application that does not allow external sign-in, and a name of another form are each
  `application_not_allowed`, with no difference an attacker can see.
- A malformed configuration fails the boot check, and at run time fails the call that reads it, closed, with an
  `InvalidArgumentException` naming the key: never a default and never another application.
- A bound redirect resolver that answers a wildcard, an `http` URL on a public host, a fragment or user information
  fails with a `LogicException`; a bound endpoint resolver that answers anything but a web URL fails building
  `ConnectionEndpoints`.
- A forged `Host`, `X-Forwarded-Host` or `X-Forwarded-Proto` changes no endpoint.

## Implementation Anchors

- `src/Applications/Application.php`, `src/Applications/ApplicationRegistry.php`,
  `src/Applications/ApplicationGate.php`, `src/Applications/ApplicationAdmission.php`,
  `src/Applications/ConfiguredApplicationPolicy.php`, `src/Applications/ConfiguredRedirectUriResolver.php`,
  `src/Applications/Enums/HandoffDelivery.php`, `src/Applications/Enums/ExternalSignIn.php`.
- `src/Contracts/ApplicationPolicy.php`, `src/Contracts/RedirectUriResolver.php`, `src/Contracts/EndpointResolver.php`.
- `src/Endpoints/ConfiguredEndpointResolver.php`, `src/Endpoints/ConnectionEndpoints.php`,
  `src/Endpoints/EndpointSettings.php`, `src/Endpoints/Enums/Endpoint.php`.
- `src/Config/Checks/ApplicationsCheck.php`, `src/Config/Checks/EndpointsCheck.php`, `src/Protocols/Navigation.php`
  (`toApplication()`, a navigation back to an application's own URL).

## Authoritative Tests

- `tests/Feature/Applications/ApplicationTest.php`, `tests/Feature/Applications/ApplicationRegistryTest.php`,
  `tests/Feature/Applications/ApplicationGateTest.php`.
- `tests/Feature/Endpoints/ConfiguredEndpointResolverTest.php`, `tests/Unit/Endpoints/ConnectionEndpointsTest.php`.
- `tests/Unit/Applications/ApplicationAdmissionTest.php`, `tests/Unit/Applications/Enums/ApplicationEnumsTest.php`.
- `tests/Feature/Config/Checks/ApplicationsCheckTest.php`, `tests/Feature/Config/Checks/EndpointsCheckTest.php`.

## Change Triggers

- A new application setting, or a change to what a redirect URI or fallback URL may be.
- A change to what the policy or the resolvers are given, or to how an answer is checked.
- A new endpoint, or a change to how the default resolver builds one.
