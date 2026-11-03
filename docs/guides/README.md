# Guides

Every guide to using the package, by what you are doing. Start with [Installation](installation.md) and
[An example application](example-application.md), which lays out every route an API needs; then
[Opt-in features and their risks](opt-in-features.md) before you turn anything on.

The security and lifecycle contracts behind the guides, for maintainers and reviewers, are in
[docs/design](../design/README.md).

## Setup

| Guide                                                         | Covers                                                                               |
|---------------------------------------------------------------|--------------------------------------------------------------------------------------|
| [Installation](installation.md)                               | Composer, the PHP extensions, the SAML library's limits, migrations and the schedule |
| [Configuration](configuration.md)                             | Every configuration key, endpoints, applications, flows and the boot check           |
| [An example application](example-application.md)              | One coherent route layout: middleware, CSRF, authorisation, ownership, the client    |
| [Opt-in features and their risks](opt-in-features.md)         | Every flow and every opt-in, what turning it on means and what it costs              |
| [Setting up an identity provider](identity-provider-setup.md) | The registration fields, and their names at Microsoft Entra ID, Okta and Google      |
| [Setting up a SAML connection](saml-connections.md)           | A SAML connection from start to finish                                               |
| [Setting up an OIDC connection](oidc-connections.md)          | Discovery import, review, client authentication, scheduled refresh and its risks     |
| [Secrets](secrets.md)                                         | Secrets encrypted at rest, rotating `APP_KEY` and binding a key management service   |

## Flows

| Guide                                                | Covers                                                                                |
|------------------------------------------------------|---------------------------------------------------------------------------------------|
| [Starting a flow](starting-a-flow.md)                | The start helper, its answer, purposes, the client's duties                           |
| [Discovery](discovery.md)                            | Starting from an email address, what it discloses, the minimum duration               |
| [Completing a flow](completing-a-flow.md)            | The completion helper, unlinked sign-ins, the contracts it asks, transactions         |
| [Completion responses](completion-responses.md)      | Statuses, redirects and headers, and what the client does with the fragment           |
| [Signing in with SAML](saml-sign-in.md)              | What a SAML response is held to: the subject, signatures, encryption, time            |
| [Signing in with OIDC](oidc-sign-in.md)              | What the provider is sent, extra parameters, re-authentication                        |
| [The OIDC callback](oidc-callback.md)                | The callback route, the `iss` parameter, errors and client authentication             |
| [OIDC ID tokens](oidc-id-tokens.md)                  | Algorithms, keys, audiences, `max_age` and times                                      |
| [OIDC claims](oidc-claims.md)                        | UserInfo, where each value comes from, the email and claim mapping                    |
| [IdP-initiated sign-in](idp-initiated-sign-in.md)    | Re-initiation of an unsolicited SAML response, and the start URL contract             |
| [Redeeming a handoff](redeeming-a-handoff.md)        | `admit()` and `redeem()`, what a redemption checks, transactions, codes of your own   |
| [Links](links.md)                                    | The link store, the `link` purpose, confirming a suspended link, listing and removing |
| [Linking by a verified domain](linking-by-domain.md) | Moving a tenant's existing members onto its provider, and what must hold              |
| [Provisioning](provisioning.md)                      | Creating a new identity for an unlinked sign-in, just in time                         |
| [Re-authenticating](reauthenticating.md)             | The `reauthenticate` purpose and the sessions contract it needs                       |
| [Provider evidence](evidence.md)                     | Opting a connection's `amr` and `acr` into your further-factor policy                 |

## Management

| Guide                                                     | Covers                                                                         |
|-----------------------------------------------------------|--------------------------------------------------------------------------------|
| [Managing connections](managing-connections.md)           | Creating, changing, enabling, disabling, deleting and migrating connections    |
| [Connections](connections.md)                             | What a connection is, protocols, registering your own, presets                 |
| [Keys and certificates](keys.md)                          | The service provider's keys and their rotation, trusting provider certificates |
| [SAML metadata](saml-metadata.md)                         | Importing metadata, signing anchors, scheduled refresh, federation aggregates  |
| [Service provider metadata](service-provider-metadata.md) | What you register at a provider, and serving it                                |
| [Domains](domains.md)                                     | Claiming, verifying and removing a domain                                      |
| [Enforcement](enforcement.md)                             | SSO-only tenants, exemptions and revoking sessions                             |
| [Fresh authentication](freshness.md)                      | The operations that ask for it, binding your own contract, testing it          |

## Integration

| Guide                                                                      | Covers                                                                    |
|----------------------------------------------------------------------------|---------------------------------------------------------------------------|
| [Integrating with `laravel-iam`](integrating-with-laravel-iam.md)          | Every seam, the transaction rule, the lock order and the adapter's checks |
| [Session provenance and the authentication context](session-provenance.md) | What a session keeps from its sign-in, and the `sso.*` context keys       |
| [Events](events.md)                                                        | Every event, its context, failures, and recording an audit trail          |
| [Localisation](localization.md)                                            | The messages the package shows, and translating them                      |
| [Logging](logging.md)                                                      | Channels, what is redacted, and logging from your own adapters            |

## Testing

| Guide                                | Covers                                                                                    |
|--------------------------------------|-------------------------------------------------------------------------------------------|
| [Testing your SSO flows](testing.md) | The fake identity providers, DNS resolver, fetcher, freshness and clock, and worked flows |
| [Clock](clock.md)                    | The clock skew, binding a clock, and a frozen clock in tests                              |

## Operations

| Guide                                                                | Covers                                                                                    |
|----------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| [Operations](operations.md)                                          | The schedule, several servers and the cache, queues, exit codes, pruning, expiry warnings |
| [Octane, queue workers and read replicas](long-running-processes.md) | Statelessness, binding your own contracts, replicas, database errors and the cache        |
| [Domain rechecks](domain-rechecks.md)                                | Checking verified domains again, lapses, and the DNS resolver                             |
| [Rate limits](rate-limits.md)                                        | The limits, their table and connection, and binding another limiter                       |
| [Outbound requests](outbound-requests.md)                            | The fetcher's address checks, an egress proxy, slow DNS                                   |
| [Single-use keys](single-use-store.md)                               | The replay store, its transactions and pruning                                            |
