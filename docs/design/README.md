# Design Notes

These notes document the package's security and lifecycle contracts that are easy to miss if you only read the
quick-start material or skim the test suite.

Each note follows the same structure:

- `Purpose`
- `Invariants`
- `Success Path`
- `Failure / Edge Cases`
- `Implementation Anchors`
- `Authoritative Tests`
- `Change Triggers`

A note that records a choice of library (`saml-library.md`, `jose-library.md`) follows `Purpose`, `Method`,
`Results`, `Findings`, `Decision`, `Implementation Anchors` and `Change Triggers` instead, since it describes a
decision and its evidence rather than a contract.

The notes are:

- `connections.md`: what a connection holds, the protocol driver contract and its registry, what makes a connection
  usable, and presets.
- `connection-settings.md`: the SAML and OIDC settings, the attribute mapping, and the management helpers that create,
  update, read, list and enable connections.
- `keys.md`: the service provider's key pairs and their rotation, and the identity provider certificates a connection
  trusts.
- `freshness.md`: the fresh authentication every operation that could widen, redirect or destroy access asks for, and
  the stable operation names.
- `administration-events.md`: the events a change to a connection, a key, a certificate, a domain or a tenant's
  enforcement reports, and when.
- `domains.md`: claiming an email domain for a connection and verifying it by DNS TXT record, the resolver contract and
  its three outcomes, one verified connection per domain, the lock order, and the predicates a domain is judged by.
- `domain-rechecks.md`: the scheduled recheck of verified domains, the grace period, the immediate suspension of linking
  and the lapse.
- `enforcement.md`: a tenant's rule that sessions in it come through its own connections, the enforcement,
  inheritance, exemption and session revocation contracts, and the version that changes with every change.
- `applications.md`: the application registry, each application's one exact redirect URI and the contract that answers
  it, the policy that says whether an application allows sign-in through an external provider, and the endpoint
  resolver that builds a connection's URLs from configuration, never from the request.
- `flows.md`: what every flow of the links and flow core shares: the links, authorisation requests and handoff codes
  tables, the distinct value types, the verified result, the contracts and their defaults, the completion's fixed steps
  and their transactions, the lock order, and the failure reasons and events by flow.
- `linking.md`: the frozen completion and redemption state machine: its stages and transactions, the lock order, the
  link and reservation states, what the application's contracts guarantee through admission, and its events.
- `session-provenance.md`: how a session's provenance is captured from the admitted `sign_in` redemption, its
  versioned stored form, and the pure projection into the `sso.*` authentication context keys.
- `evidence.md`: what the identity provider's authentication context counts for: each connection's evidence policy, how
  a result is judged at redemption and from its own assertion alone, and what a redeemer offers its further factor.
- `links.md`, `authorization-requests.md`, `discovery.md`, `completion.md`, `handoffs.md`, `completion-responses.md` and
  `connection-lifecycle.md`: the link store, starting a flow, discovery by email domain, the completion pipeline,
  handoff codes and their redemption, the completion's response values, and disabling, deleting and changing the trust
  of a connection, each on the model `flows.md` lays down.
- `storage.md`: where the package's tables live, why they share one connection, how the models and the published
  migrations choose the same connection and table names, and the transaction rule an adapter follows.
- `configuration.md`: the feature switches, the configuration checked at boot and by `sso:check` for what is enabled,
  the application and endpoint settings, and how each part of the package registers its settings and its check.
- `outcomes.md`: how the package's contracts and helpers answer: refusals as values, the result and outcome types,
  throttling as an outcome, and what an exception means.
- `clock.md`: the one clock every time check reads, the clock skew, and the frozen clock for tests.
- `single-use-store.md`: how a key is recorded once until its expiry, atomically, and why only `recorded` lets a flow
  proceed.
- `secrets.md`: how secrets are encrypted at rest, masked on read, kept out of logs, exceptions and events, and
  compared in constant time.
- `outbound-requests.md`: the one fetcher every request to an identity provider goes through, the addresses it refuses,
  the pinned address, redirects, caps and credentials by purpose.
- `event-model.md`: the context every package event carries, the one projection that builds it, dispatch after commit,
  and the one failure event per refused operation.
- `logging.md`: the sanitiser for provider diagnostics and the redaction applied to every log call and its context.
- `rate-limits.md`: the limits on each flow, counted in the database, always on, and throttling as an outcome.
- `localization.md`: the messages put in front of a consumer, translated under the package's namespace.
- `saml-library.md`: why the package parses and verifies SAML with `simplesamlphp/saml2` v6, the adversarial fixture
  results behind the choice, and the conditions the package's adapter holds the library to.
- `saml-driver.md`: the `saml2` driver as a whole, each call and its collaborator, and how it plugs into the completion
  without bypassing consumption, the lock order or enforcement.
- `saml-adapter.md`: the one namespace that calls the SAML library, its hardened parsing, caps and structure checks,
  the pinned verifier and the SSO-6.7 signature and encryption policy, and the values a read response is given as.
- `saml-requests.md`, `saml-responses.md`, `idp-initiated.md`, `service-provider-metadata.md` and `metadata-refresh.md`:
  the SAML driver's `AuthnRequest` and its bindings, the validation of a solicited response and its replay record,
  re-initiation from an unsolicited response, the service provider's metadata, and metadata import, scheduled refresh,
  expiry and the trust version, each on the driver `saml-driver.md` and the adapter `saml-adapter.md` lay down.
- `jose-library.md`: why the package verifies ID tokens and signs client assertions with `web-token/jwt-library`, the
  hostile-token and clock results behind the choice, and the rules the package's adapter adds around it.
- `jose-adapter.md`: the one namespace that calls the JOSE library, how it reads a token, admits and selects a key,
  verifies a signature and signs a client assertion, and what it leaves to the package's own checks.
- `oidc-driver.md`: the `oidc` driver as a whole, each call and its collaborator, the values they hand each other,
  where a connection's JWKS and refresh state are kept, and the limits every OIDC connection is held to.
- `oidc-discovery.md`, `oidc-requests.md`, `oidc-callback.md`, `oidc-id-tokens.md`, `oidc-claims.md` and
  `oidc-relying-party.md`: discovery import, the JWKS, its refetch on an unknown `kid` and the scheduled refresh; the
  authorisation code request; the callback and the token request; the ID token's validation; UserInfo, provider tokens
  and the email; and what an administrator registers at the provider, each on the driver `oidc-driver.md` and the
  adapter `jose-adapter.md` lay down.
- `operations.md`: the operations schedule and its opt-in cache mutexes, pruning and its retention, batches, work cap
  and partial progress, the expiry warnings and their at-least-once delivery, and who cleans up an application's own
  store.
- `long-running-processes.md`: what the package promises of the processes it runs in and how the suite proves it: no
  session, nothing kept between requests or jobs, the write connection, database errors as server errors, and a cache
  it never needs.
- `performance-budgets.md`: the deterministic query budgets of every operation and whole flow on both connections,
  bounded growth across many rows, and the scheduled benches, where their environment and versions appear and why no
  time gates CI.
- `transaction-ownership.md`: each transaction of a completion, a redemption and an administrative change, what it
  writes, which events belong to it, and what stands when it rolls back.
- `standalone-acceptance.md`: how the package is shown to stand alone: what each seam's default does with no sibling
  installed, what an application must supply to go further, and how default and adapter acceptance are kept apart.
- `requirements.md`: the requirement closure matrix: every clause of the requirements, split into obligations that can
  each be proven on their own, with the code, the test and assertion, and the documentation behind each, its status, and
  the recorded decision behind each reconciled row. It follows its own structure (`Purpose`, `Summary`,
  `Reading the Matrix`, the twelve sections, the context, `Recorded Decisions` and `Change Triggers`) rather than the
  one above.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
