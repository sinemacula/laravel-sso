# Design Notes

These notes document the package's security and lifecycle contracts that are easy to miss if you only read the
quick-start material or skim the test suite.

Each note is intentionally short and follows the same structure:

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

The current note set is:

- `connections.md`: what a connection holds, the protocol driver contract and its registry, what makes a connection
  usable, and presets.
- `connection-settings.md`: the SAML and OIDC settings, the attribute mapping, and the management helpers that create,
  update, read, list and enable connections.
- `keys.md`: the service provider's key pairs and their rotation, and the identity provider certificates a connection
  trusts.
- `freshness.md`: the fresh authentication every operation that could widen, redirect or destroy access asks for, and
  the stable operation names.
- `administration-events.md`: the events a change to a connection, a key or a certificate reports, and when.
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
- `jose-library.md`: why the package verifies ID tokens and signs client assertions with `web-token/jwt-library`, the
  hostile-token and clock results behind the choice, and the rules the package's adapter adds around it.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
