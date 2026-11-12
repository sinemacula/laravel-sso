# Standalone Acceptance

## Purpose

This note records how the package is shown to stand alone (CTX/a): what each seam's default does in an application with
no sibling installed, what an application must supply before a flow goes further, and how the suite keeps default and
adapter acceptance apart, so that a fully faked happy path is never taken for proof of independence.

## Invariants

- No sibling is reachable at run time: no sibling package is installed, none of its classes autoloads or is declared, no
  autoloader knows its namespace, and the application holds no `authentication`, `mfa` or `iam` configuration. The
  package's architecture test covers its source; `DefaultBindingsFlowsTest` covers the running application.
- Every acceptance test extends `Tests\StandaloneTestCase`: no sibling, no package discovered, no session in any
  middleware group, and no binding beyond what the provider makes. A test that replaces a seam does so itself and says
  so, and asserts every other seam is still on its default.
- Only the outside world is ever faked: `Testing\FakeSamlIdentityProvider`, `Testing\FakeOpenIdProvider`,
  `Testing\FakeFetcher` and `Testing\FakeDnsResolver`. The package's orchestration, storage, transactions and protocol
  implementations are the real ones. An OIDC completion reaches its provider, so its fake fetcher is the one seam a
  default-path test replaces; SAML, and every OIDC start, needs none.
- The default-path tests are the primary claim and use nothing under `tests/Fixtures/Standalone`. The integration test
  shows that the seams join up; it is not what shows the package stands alone.
- The routes are the application's. The package adds none, and every URL it publishes comes from configuration, so the
  tests serve its helpers from routes of their own, in no middleware group.
- What a sibling would consume is an event with enough context to act on: the integration test asserts it from the
  events alone, querying nothing back, and that no event carries a code, a verifier, a subject or an email.
- Nothing is shaped to one consumer's applications, tenant tree, identity providers or attribute names: presets hold
  only public providers' documented endpoints, shared issuers are listed by requirement, the tenant tree is the
  application's (`Contracts\EnforcementInheritance`) and custom mapping keys are the application's own
  (`sso.mapping.custom_attributes`). No test can show a negative like this one, so it is proven by review
  ([RD-35](requirements.md#recorded-decisions)): before each release, `src/`, `config/`, `lang/` and the presets are
  read for a name, a default or a branch that only one consumer needs, and any change to the presets, the linking
  settings or the inheritance seam triggers the same review (the requirement closure matrix's CTX/e and its change
  triggers).

What each default does, and what an application supplies to go further:

| Seam                       | Default                         | What it does alone                                                                                   | What an application supplies                                                           |
|----------------------------|---------------------------------|------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| `SingleUseStore`           | `DatabaseSingleUseStore`        | Records and refuses a key on the real table, in the caller's transaction                             | Nothing; a store on another connection is outside the package's transactions           |
| `AttemptLimiter`           | `DatabaseAttemptLimiter`        | Limits in the database, with no cache                                                                | Nothing                                                                                |
| `Fetcher`                  | `GuzzleFetcher`                 | Makes every outbound request, under its checks                                                       | Nothing                                                                                |
| `DnsResolver`              | `SystemDnsResolver`             | Looks up TXT records; `lookup_failed` when it cannot answer                                          | Nothing                                                                                |
| `HostResolver`             | `SystemHostResolver`            | Resolves the fetcher's hosts through the system resolver, with no timeout of its own                 | Nothing; its own for a bounded lookup, DNSSEC or DNS over HTTPS                        |
| `Clock`                    | `SystemClock`                   | Follows Laravel's clock                                                                              | Nothing                                                                                |
| `SecretEncrypter`          | `LaravelSecretEncrypter`        | Encrypts stored secrets with Laravel's encrypter under `app.key`                                     | Nothing; its own for a key management service                                          |
| `HandoffIssuer`            | `DatabaseHandoffStore`          | Issues codes the package's redemption redeems                                                        | Nothing; another must store the reservation's binding and write inside the transaction |
| `Enforcement`              | `DatabaseEnforcement`           | Reads the database; off until a tenant turns it on                                                   | Nothing                                                                                |
| `EnforcementInheritance`   | `OwnTenantInheritance`          | Applies each tenant's own rule                                                                       | A tenant tree, to inherit one                                                          |
| `EnforcementExemption`     | `NoExemptions`                  | Exempts nobody                                                                                       | Whom to exempt                                                                         |
| `SessionRevocation`        | `NoSessionRevocation`           | Deliberately does nothing; a change still succeeds and reports                                       | Its sessions' revocation, on the storage connection, to end what a change disallows    |
| `ApplicationPolicy`        | `ConfiguredApplicationPolicy`   | Allows what `sso.applications` says                                                                  | Nothing                                                                                |
| `RedirectUriResolver`      | `ConfiguredRedirectUriResolver` | Answers the configured URI                                                                           | Nothing                                                                                |
| `EndpointResolver`         | `ConfiguredEndpointResolver`    | Builds URLs from configuration, never the request                                                    | Nothing                                                                                |
| `ProviderSessionDeadline`  | `ProviderDeadlineLimitsSession` | The provider's deadline limits the session                                                           | An answer of its own, to keep sessions apart from the provider's                       |
| `LinkLimit`                | `OneLinkPerConnection`          | One link per identity and connection                                                                 | A limit of its own                                                                     |
| `Linker`                   | `NoLinks`                       | Resolves nothing, so a `sign_in` ends `unlinked`, or hands off unlinked where the application allows | `LinkStore`, or a wrapper providing `LinkStorage`, to link at all                      |
| `Freshness`                | `RefusingFreshness`             | Refuses every operation of SSO-2.12, `freshness_required`                                            | How it judges its caller, before any management helper or `link` start                 |
| `LinkEligibility`          | `RefusingLinkEligibility`       | Refuses every `link`, `link_ineligible`                                                              | Who may link                                                                           |
| `LinkConfirmation`         | `RefusingLinkConfirmation`      | Refuses a `link` of an identity holding a domain link, `independent_authentication_required`         | How a caller stands apart from those links                                             |
| `LinkEmailMatcher`         | `NoEmailMatches`                | Matches nobody, so linking by a verified domain reserves nothing                                     | Whom an email belongs to                                                               |
| `PrincipalScope`           | `RefusingPrincipalScope`        | Knows no principals: a domain link's `sign_in` is `principal_scope_unknown`, and nothing is reserved | Its principals                                                                         |
| `TenantMembership`         | `NoTenantMembership`            | Holds no membership, so nothing is reserved                                                          | Its memberships                                                                        |
| `EvidencePolicy`           | `InsufficientEvidence`          | Accepts nothing a provider asserted                                                                  | What it accepts                                                                        |
| `ReauthenticationSessions` | `NoReauthenticationSessions`    | Finds no session, so a `reauthenticate` start is `session_ineligible`                                | Its sessions                                                                           |

## Success Path

1. On nothing but the defaults, a configured SAML or OIDC start produces the protocol's redirect, discovery routes by a
   verified domain when the feature is on, service provider metadata and JWKS are served, and `sso:prune` and
   `sso:keys:expiring` run.
2. A completion through `NoLinks` offers `ResultUnlinked` synchronously, with no transaction open and no code, then ends
   with the `unlinked` failure code on the redirect, with no code on it; with `unlinked_handoffs` on, the default store
   issues a code that the default redemption redeems.
3. Each seam is replaced on its own, with a contract-conforming fake or a wrapper of the package's own, through real
   orchestration: the seam is shown to be used, its guarantees to hold, and every other seam to be on its default.
4. `ApplicationSeams` binds every seam an application stands behind at once, and each purpose runs from start to
   redemption over both protocols, with provisioning through the helper, enforcement with revocation, and linking by a
   verified domain from reservation to activation.

## Failure / Edge Cases

- A default deep inside a flow is reached only once what comes before it has answered, so the test proving it replaces
  those seams and names them: `RefusingLinkEligibility` needs a fresh caller, and a linker that can write a link;
  `NoTenantMembership` needs a sole match within the tenant. "On its own" means what the seam's flow lets it mean.
- `NoSessionRevocation` cannot be reached by a change on the defaults alone, since `RefusingFreshness` lets no caller
  make one, so that test replaces `Freshness`, and nothing else.
- Domain linking with `NoLinks` is refused by `sso:check`, by the boot check as a request is served or a worker starts,
  and by `LinkingPolicyService`. A `link` completion and a `link` redemption with no storage are `LogicException`s, with
  no link and no code written: the request a completion consumed stays consumed, since that committed first, and the
  code a redemption was given stays unconsumed and redeems once storage is bound again.
- A linker used for mutations must provide `LinkStorage`: a resolver-only linker answers a `sign_in`, and is refused by
  everything that would write a link.
- An issuer must preserve a reservation's binding and issue in the transaction: one answering no reference rolls T2
  back, with neither the reservation nor the code kept, and one that throws in the final continuation rolls T3 back,
  leaving what T2 committed.
- A `SessionRevocation` writing through the storage connection commits and rolls back with the change. One that throws
  rolls the change back, and nothing is reported.
- A `SingleUseStore` on another connection is outside the package's transactions, as its guide warns: a record made
  inside a transaction that rolls back is kept, so a code that rollback left unconsumed is then `replayed`. It fails
  closed.
- Seams that hold no application state (`EnforcementInheritance`, `EnforcementExemption`, `ApplicationPolicy`,
  `RedirectUriResolver`, `EndpointResolver`, `LinkLimit`) stay on their defaults in the integration test, as most
  applications leave them; each has its own tests under its feature.

## Implementation Anchors

- `src/SsoServiceProvider.php`: every default, bound only if nothing was bound before.
- `src/Links/LinkStorageBinding.php` and `src/Linking/LinkingCheck.php`: the storage pairing and its refusal.
- `tests/StandaloneTestCase.php`: the isolated application and its assertions.
- `tests/Concerns/FlowRoutes.php`: the routes an application adds, and a client for them. Its
  `prepareFlows()` binds a real application's contracts, so the tests here configure the application themselves.
- `tests/Fixtures/Standalone/`: the application-supplied seams, and `ApplicationSeams`, which binds them all.

## Authoritative Tests

- `tests/Integration/Standalone/DefaultBindingsFlowsTest.php`
- `tests/Integration/Standalone/DefaultBindingsRefusalsTest.php`
- `tests/Integration/Standalone/ApplicationBindingsTest.php`
- `tests/Integration/Standalone/ApplicationIntegrationTest.php`
- `tests/Integration/Support/StandaloneTestCaseTest.php`
- `tests/Unit/Architecture/ApplicationBoundaryTest.php`: nothing checks a permission, signs a person in, keeps a session
  or issues a token.
- `tests/Unit/SsoServiceProviderTest.php` `testEverySeamBoundBeforeIsKept`: a binding made before the provider
  registers is kept, for every seam.

## Change Triggers

- A new seam, or a new default for one: it joins `StandaloneTestCase::DEFAULT_BINDINGS`, the table above and a test of
  what it does alone.
- A dependency on a sibling's class, interface or configuration, in any form.
- A new operation of SSO-2.12: `DefaultBindingsRefusalsTest` fails until it makes that operation's change.
- A route, a session or a cache added to any flow.
- A change to what a contract requires of an adapter: the fixture that conforms to it, and the test of its guarantee.
- An event losing what a sibling needs to act on without querying back.
