# Configuration

The package's settings live in the published `config/sso.php`, under `sso.`. Every feature is off until the application
turns it on, and every security check of a feature that is on is always on. A value that is malformed or out of range
fails closed, naming the key, when it is used, and the configuration of what is enabled is checked when the application
boots (see [Checking the configuration](#checking-the-configuration)). Settings are read each time they are used.

| Key                                                  | Default                                         | Env                                   | See                                             |
|------------------------------------------------------|-------------------------------------------------|---------------------------------------|-------------------------------------------------|
| `storage.connection`                                 | `null`                                          | `SSO_STORAGE_CONNECTION`              | [Storage](#storage)                             |
| `features.saml2`                                     | `false`                                         | `SSO_SAML2`                           | [Features](#features)                           |
| `features.oidc`                                      | `false`                                         | `SSO_OIDC`                            | [Features](#features)                           |
| `features.discovery`                                 | `false`                                         | `SSO_DISCOVERY`                       | [Features](#features)                           |
| `features.enforcement`                               | `false`                                         | `SSO_ENFORCEMENT`                     | [Features](#features)                           |
| `features.encrypted_assertions`                      | `false`                                         | `SSO_ENCRYPTED_ASSERTIONS`            | [Features](#features)                           |
| `features.metadata_refresh`                          | `false`                                         | `SSO_METADATA_REFRESH`                | [Features](#features)                           |
| `features.idp_initiated`                             | `false`                                         | `SSO_IDP_INITIATED`                   | [Features](#features)                           |
| `features.domain_linking`                            | `false`                                         | `SSO_DOMAIN_LINKING`                  | [Features](#features)                           |
| `endpoints.base_url`                                 | `null`                                          | `SSO_BASE_URL`                        | [Endpoints](#endpoints)                         |
| `endpoints.paths.assertion_consumer_service`         | `/auth/sso/connections/{connection}/assertions` |                                       | [Endpoints](#endpoints)                         |
| `endpoints.paths.callback`                           | `/auth/sso/connections/{connection}/callback`   |                                       | [Endpoints](#endpoints)                         |
| `endpoints.paths.metadata`                           | `/auth/sso/connections/{connection}/metadata`   |                                       | [Endpoints](#endpoints)                         |
| `applications`                                       | `[]`                                            |                                       | [Applications](#applications)                   |
| `clock.skew_seconds`                                 | `60`                                            | `SSO_CLOCK_SKEW_SECONDS`              | [Clock](clock.md)                               |
| `connections.table`                                  | `sso_connections`                               | `SSO_CONNECTIONS_TABLE`               | [Connections](connections.md)                   |
| `keys.table`                                         | `sso_keys`                                      | `SSO_KEYS_TABLE`                      | [Keys and certificates](keys.md)                |
| `keys.rsa_bits`                                      | `3072`                                          | `SSO_KEYS_RSA_BITS`                   | [Keys and certificates](keys.md)                |
| `keys.certificate_days`                              | `730`                                           | `SSO_KEYS_CERTIFICATE_DAYS`           | [Keys and certificates](keys.md)                |
| `keys.overlap_seconds`                               | `604800`                                        | `SSO_KEYS_OVERLAP_SECONDS`            | [Keys and certificates](keys.md)                |
| `keys.expiry_warning_days`                           | `30`                                            | `SSO_KEYS_EXPIRY_WARNING_DAYS`        | [Keys and certificates](keys.md)                |
| `mapping.max_value_length`                           | `1024`                                          | `SSO_MAPPING_MAX_VALUE_LENGTH`        | [Managing connections](managing-connections.md) |
| `mapping.max_values`                                 | `100`                                           | `SSO_MAPPING_MAX_VALUES`              | [Managing connections](managing-connections.md) |
| `mapping.max_custom_attributes`                      | `20`                                            | `SSO_MAPPING_MAX_CUSTOM_ATTRIBUTES`   | [Managing connections](managing-connections.md) |
| `freshness.max_age_seconds.<operation>`              | `300` each                                      |                                       | [Fresh authentication](freshness.md)            |
| `single_use.table`                                   | `sso_single_use_keys`                           | `SSO_SINGLE_USE_TABLE`                | [Single-use keys](single-use-store.md)          |
| `fetcher.timeout_seconds`                            | `10`                                            | `SSO_FETCHER_TIMEOUT_SECONDS`         | [Outbound requests](outbound-requests.md)       |
| `fetcher.connect_timeout_seconds`                    | `5`                                             | `SSO_FETCHER_CONNECT_TIMEOUT_SECONDS` | [Outbound requests](outbound-requests.md)       |
| `fetcher.max_response_bytes`                         | `1048576`                                       | `SSO_FETCHER_MAX_RESPONSE_BYTES`      | [Outbound requests](outbound-requests.md)       |
| `fetcher.max_redirects`                              | `3`                                             | `SSO_FETCHER_MAX_REDIRECTS`           | [Outbound requests](outbound-requests.md)       |
| `fetcher.refused_ranges`                             | `[]`                                            |                                       | [Outbound requests](outbound-requests.md)       |
| `logging.channel`                                    | `null`                                          | `SSO_LOG_CHANNEL`                     | [Logging](logging.md)                           |
| `logging.max_diagnostic_length`                      | `512`                                           | `SSO_LOG_MAX_DIAGNOSTIC_LENGTH`       | [Logging](logging.md)                           |
| `logging.redacted_keys`                              | `[]`                                            |                                       | [Logging](logging.md)                           |
| `rate_limits.table`                                  | `sso_rate_limits`                               | `SSO_RATE_LIMITS_TABLE`               | [Rate limits](rate-limits.md)                   |
| `rate_limits.connection`                             | `null`                                          | `SSO_RATE_LIMITS_CONNECTION`          | [Storage](#storage)                             |
| `rate_limits.authorization_request.per_ip`           | 30 per 60 s                                     |                                       | [Rate limits](rate-limits.md)                   |
| `rate_limits.authorization_request.per_email_domain` | 300 per 60 s                                    |                                       | [Rate limits](rate-limits.md)                   |
| `rate_limits.completion.per_ip`                      | 30 per 60 s                                     |                                       | [Rate limits](rate-limits.md)                   |
| `rate_limits.completion.per_connection`              | 600 per 60 s                                    |                                       | [Rate limits](rate-limits.md)                   |
| `rate_limits.redemption.per_ip`                      | 30 per 60 s                                     |                                       | [Rate limits](rate-limits.md)                   |
| `rate_limits.metadata.per_connection`                | 10 per 3600 s                                   |                                       | [Rate limits](rate-limits.md)                   |
| `rate_limits.domain_check.per_connection`            | 30 per 3600 s                                   |                                       | [Rate limits](rate-limits.md)                   |

## Storage

Every package table lives on `storage.connection` (`null` or empty for the default connection): the models read and
write them there, and the published migrations create them there. The rate limit counters live on
`rate_limits.connection` when it names one, so they can stay out of a transaction a refused flow rolls back, and on the
storage connection otherwise. Each table's name is set in its own section and defaults to an `sso_` prefix.

The tables share one connection because a completion, a redemption, a connection's lifecycle change and a link's
activation each write several of them in one transaction, which two connections cannot commit as one. An adapter that
must commit with the package (a session revocation, a handoff redeemed by your sign-in, a link activated with a session)
writes through this same Laravel connection, inside the transaction the package opens; reaching the same database
through another connection is not atomic.

A value that is neither a connection name nor `null` or empty fails closed when a model is built, as does a malformed
table name. Keep the settings fixed while the application runs: moving or renaming the tables is a deploy, with a
migration you write and a restart of every worker.

## Features

`features` holds a switch per feature, each `false` by default. `saml2` and `oidc` turn the protocols on; with neither
on the package is not in use, and nothing but these switches is checked. Every other feature needs a protocol on, and
`encrypted_assertions` and `idp_initiated` need `saml2`. A feature that is on lets an application or a connection opt
into it; it never opts in for them.

Each switch is `true` or `false` (`1` and `0`, as numbers or strings, are read the same). Anything else, a switch the
package does not have (a misspelt one would leave the feature off), or a feature on without the protocol it needs fails
the boot check.

## Endpoints

The package builds each connection's assertion consumer service, OIDC callback, metadata URL and service provider
entity id from `endpoints.base_url` and the path pattern of each endpoint, never from the request's host or headers.
The base URL is an absolute `https` URL (or `http` on `127.0.0.1` or `[::1]` for development) with no query or
fragment, and is required while a protocol is on; it may carry a path prefix. Each pattern is an absolute path holding
`{connection}` once, with no query, fragment, other placeholder or dot segment, and the patterns differ. Route the same
paths to the package's helpers in your application; an application with another layout binds its own endpoint
resolver.

## Applications

`applications` registers the applications people sign into through a connection, by a lower-case name: your own front
ends, a fixed set deployed with the code. Each client's connections are rows in the database, not entries here, and
nothing in a request chooses among these values.

```php
'applications' => [
    'web' => [
        'redirect_uri'     => 'https://app.example.com/auth/sso/complete',
        'external_sign_in' => true,
    ],
    'mobile' => [
        'redirect_uri'        => 'com.example.app:/auth/sso/complete',
        'external_sign_in'    => true,
        'delivery'            => 'fragment',
        'discovery'           => ['enabled' => true, 'fallback_url' => 'com.example.app:/sign-in'],
        'unlinked_handoffs'   => false,
        'handoff_ttl_seconds' => 60,
    ],
],
```

| Setting                  | Default    | Meaning                                                                                    |
|--------------------------|------------|--------------------------------------------------------------------------------------------|
| `redirect_uri`           | required   | The one URI a completion redirects to, compared as an exact string                         |
| `external_sign_in`       | `false`    | Whether the application allows sign-in through an external provider                        |
| `delivery`               | `fragment` | Where the handoff code goes on the redirect URI: `fragment` or `query`                     |
| `discovery.enabled`      | `false`    | Whether the application offers discovery by email domain (with the `discovery` feature on) |
| `discovery.fallback_url` | `null`     | Where a discovery miss leads; required while discovery is offered and the feature is on    |
| `unlinked_handoffs`      | `false`    | Whether a sign-in that resolves to no identity is still handed off                         |
| `handoff_ttl_seconds`    | `60`       | The handoff code's lifetime, 1 to 300 seconds                                              |

A redirect URI is `https`, `http` on `127.0.0.1` or `[::1]`, or a private-use scheme a native application registers
(a lower-case scheme with a dot, RFC 8252), with no user information, fragment or wildcard; the fallback URL follows the
same rules. The exact URI is answered by the `RedirectUriResolver` contract, which defaults to this setting: bind your
own to answer a per-client address without a schema change. Under `laravel-iam`, whether an application allows
external sign-in comes from `laravel-authentication`'s per-application methods instead of `external_sign_in`. The
start URL an unsolicited SAML response is sent to for re-initiation is a connection's setting, since such a response
names no application.

## Checking the configuration

The configuration of what is enabled is checked when the application boots to serve a request, and a problem stops the
boot with an `InvalidConfigurationException` that lists every problem as `[subject] message`.

In the console it is checked as a worker or scheduler command starts: `queue:work`, `queue:listen`, `horizon` (and the
supervisors and workers it starts), `schedule:run`, `schedule:work`, `schedule:test`, `octane:start` and the Octane
server commands. A problem fails the command with the same exception, so it exits before it takes a job or runs a
scheduled task, and your process manager reports it rather than the first job that needs SSO. Every other command
runs, so a misconfigured application can still run `sso:check`, its migrations, `vendor:publish`, `config:clear` and
the other cache commands to put it right.

Run `sso:check` in a deploy pipeline or a readiness probe to find a problem before a worker or a request does:

```bash
php artisan sso:check
```

It prints `[subject] OK`, `[subject] not enabled` for what is off, or one line per problem, and exits `1` when there
is a problem. The subjects are `features` (always checked), `extensions`, `storage`, `endpoints`, `applications`,
`clock`, `secrets`, `fetcher`, `logging`, `rate_limits`, `freshness`, `keys` and `mapping` (each checked while a
protocol is on). The check reads configuration only: it opens no database connection and prints no secret or
configured value. What the last eight check is in their guides: [Clock](clock.md), [Secrets](secrets.md),
[Outbound requests](outbound-requests.md), [Logging](logging.md), [Rate limits](rate-limits.md),
[Fresh authentication](freshness.md), [Keys and certificates](keys.md) and
[Managing connections](managing-connections.md).
