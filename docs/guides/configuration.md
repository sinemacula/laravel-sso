# Configuration

The package's settings live in the published `config/sso.php`, under `sso.`. Every feature is off until the application
turns it on, except the scheduled metadata refresh, which is on and has nothing to do until a protocol is on (see
[Features](#features)). Every security check of a feature that is on is always on. A value that is malformed or out of
range fails closed, naming the key, when it is used, and the configuration of what is enabled is checked when the
application boots (see [Checking the configuration](#checking-the-configuration)). Settings are read each time they are
used.

| Key                                                  | Default                                         | Env                                           | See                                             |
|------------------------------------------------------|-------------------------------------------------|-----------------------------------------------|-------------------------------------------------|
| `storage.connection`                                 | `null`                                          | `SSO_STORAGE_CONNECTION`                      | [Storage](#storage)                             |
| `features.saml2`                                     | `false`                                         | `SSO_SAML2`                                   | [Features](#features)                           |
| `features.oidc`                                      | `false`                                         | `SSO_OIDC`                                    | [Features](#features)                           |
| `features.discovery`                                 | `false`                                         | `SSO_DISCOVERY`                               | [Features](#features)                           |
| `features.enforcement`                               | `false`                                         | `SSO_ENFORCEMENT`                             | [Features](#features)                           |
| `features.encrypted_assertions`                      | `false`                                         | `SSO_ENCRYPTED_ASSERTIONS`                    | [Features](#features)                           |
| `features.metadata_refresh`                          | `true`                                          | `SSO_METADATA_REFRESH`                        | [Features](#features)                           |
| `features.idp_initiated`                             | `false`                                         | `SSO_IDP_INITIATED`                           | [Features](#features)                           |
| `features.domain_linking`                            | `false`                                         | `SSO_DOMAIN_LINKING`                          | [Features](#features)                           |
| `endpoints.base_url`                                 | `null`                                          | `SSO_BASE_URL`                                | [Endpoints](#endpoints)                         |
| `endpoints.paths.assertion_consumer_service`         | `/auth/sso/connections/{connection}/assertions` |                                               | [Endpoints](#endpoints)                         |
| `endpoints.paths.callback`                           | `/auth/sso/connections/{connection}/callback`   |                                               | [Endpoints](#endpoints)                         |
| `endpoints.paths.jwks`                               | `/auth/sso/connections/{connection}/jwks`       |                                               | [Endpoints](#endpoints)                         |
| `endpoints.paths.metadata`                           | `/auth/sso/connections/{connection}/metadata`   |                                               | [Endpoints](#endpoints)                         |
| `applications`                                       | `[]`                                            |                                               | [Applications](#applications)                   |
| `clock.skew_seconds`                                 | `60`                                            | `SSO_CLOCK_SKEW_SECONDS`                      | [Clock](clock.md)                               |
| `saml2.max_response_bytes`                           | `262144`                                        | `SSO_SAML2_MAX_RESPONSE_BYTES`                | [Signing in with SAML](saml-sign-in.md)         |
| `saml2.max_xml_bytes`                                | `196608`                                        | `SSO_SAML2_MAX_XML_BYTES`                     | [Signing in with SAML](saml-sign-in.md)         |
| `saml2.max_decrypted_bytes`                          | `131072`                                        | `SSO_SAML2_MAX_DECRYPTED_BYTES`               | [Signing in with SAML](saml-sign-in.md)         |
| `saml2.issue_instant_max_age_seconds`                | `300`                                           | `SSO_SAML2_ISSUE_INSTANT_MAX_AGE_SECONDS`     | [Signing in with SAML](saml-sign-in.md)         |
| `oidc.max_id_token_bytes`                            | `16384`                                         | `SSO_OIDC_MAX_ID_TOKEN_BYTES`                 | [OIDC limits](#oidc-limits)                     |
| `oidc.max_jwks_bytes`                                | `65536`                                         | `SSO_OIDC_MAX_JWKS_BYTES`                     | [OIDC limits](#oidc-limits)                     |
| `oidc.max_jwks_keys`                                 | `50`                                            | `SSO_OIDC_MAX_JWKS_KEYS`                      | [OIDC limits](#oidc-limits)                     |
| `oidc.max_discovery_bytes`                           | `65536`                                         | `SSO_OIDC_MAX_DISCOVERY_BYTES`                | [OIDC limits](#oidc-limits)                     |
| `oidc.max_token_response_bytes`                      | `65536`                                         | `SSO_OIDC_MAX_TOKEN_RESPONSE_BYTES`           | [OIDC limits](#oidc-limits)                     |
| `oidc.max_userinfo_bytes`                            | `65536`                                         | `SSO_OIDC_MAX_USERINFO_BYTES`                 | [OIDC limits](#oidc-limits)                     |
| `oidc.max_callback_parameter_bytes`                  | `2048`                                          | `SSO_OIDC_MAX_CALLBACK_PARAMETER_BYTES`       | [OIDC limits](#oidc-limits)                     |
| `oidc.max_callback_query_bytes`                      | `8192`                                          | `SSO_OIDC_MAX_CALLBACK_QUERY_BYTES`           | [OIDC limits](#oidc-limits)                     |
| `oidc.max_callback_parameters`                       | `16`                                            | `SSO_OIDC_MAX_CALLBACK_PARAMETERS`            | [OIDC limits](#oidc-limits)                     |
| `oidc.jwks_refetch_cooldown_seconds`                 | `300`                                           | `SSO_OIDC_JWKS_REFETCH_COOLDOWN_SECONDS`      | [OIDC limits](#oidc-limits)                     |
| `oidc.id_token_max_age_seconds`                      | `300`                                           | `SSO_OIDC_ID_TOKEN_MAX_AGE_SECONDS`           | [OIDC limits](#oidc-limits)                     |
| `oidc.token_timeout_seconds`                         | `10`                                            | `SSO_OIDC_TOKEN_TIMEOUT_SECONDS`              | [OIDC limits](#oidc-limits)                     |
| `oidc.userinfo_timeout_seconds`                      | `10`                                            | `SSO_OIDC_USERINFO_TIMEOUT_SECONDS`           | [OIDC limits](#oidc-limits)                     |
| `metadata.max_bytes`                                 | `1048576`                                       | `SSO_METADATA_MAX_BYTES`                      | [SAML metadata](saml-metadata.md)               |
| `metadata.refresh_interval_seconds`                  | `86400`                                         | `SSO_METADATA_REFRESH_INTERVAL_SECONDS`       | [SAML metadata](saml-metadata.md)               |
| `metadata.backoff_initial_seconds`                   | `300`                                           | `SSO_METADATA_BACKOFF_INITIAL_SECONDS`        | [SAML metadata](saml-metadata.md)               |
| `metadata.backoff_max_seconds`                       | `21600`                                         | `SSO_METADATA_BACKOFF_MAX_SECONDS`            | [SAML metadata](saml-metadata.md)               |
| `metadata.stale_limit_seconds`                       | `2592000`                                       | `SSO_METADATA_STALE_LIMIT_SECONDS`            | [SAML metadata](saml-metadata.md)               |
| `metadata.claim_seconds`                             | `300`                                           | `SSO_METADATA_CLAIM_SECONDS`                  | [SAML metadata](saml-metadata.md)               |
| `metadata.queue.connection`                          | `null`                                          | `SSO_METADATA_QUEUE_CONNECTION`               | [SAML metadata](saml-metadata.md)               |
| `metadata.queue.name`                                | `null`                                          | `SSO_METADATA_QUEUE`                          | [SAML metadata](saml-metadata.md)               |
| `metadata.queue.timeout_seconds`                     | `60`                                            | `SSO_METADATA_QUEUE_TIMEOUT_SECONDS`          | [SAML metadata](saml-metadata.md)               |
| `metadata.queue.tries`                               | `1`                                             | `SSO_METADATA_QUEUE_TRIES`                    | [SAML metadata](saml-metadata.md)               |
| `connections.table`                                  | `sso_connections`                               | `SSO_CONNECTIONS_TABLE`                       | [Connections](connections.md)                   |
| `keys.table`                                         | `sso_keys`                                      | `SSO_KEYS_TABLE`                              | [Keys and certificates](keys.md)                |
| `keys.rsa_bits`                                      | `3072`                                          | `SSO_KEYS_RSA_BITS`                           | [Keys and certificates](keys.md)                |
| `keys.certificate_days`                              | `730`                                           | `SSO_KEYS_CERTIFICATE_DAYS`                   | [Keys and certificates](keys.md)                |
| `keys.overlap_seconds`                               | `604800`                                        | `SSO_KEYS_OVERLAP_SECONDS`                    | [Keys and certificates](keys.md)                |
| `keys.expiry_thresholds`                             | `[30, 14, 7, 1, 0]`                             |                                               | [Operations](operations.md)                     |
| `keys.expiry_claim_seconds`                          | `300`                                           | `SSO_KEYS_EXPIRY_CLAIM_SECONDS`               | [Operations](operations.md)                     |
| `domains.table`                                      | `sso_domains`                                   | `SSO_DOMAINS_TABLE`                           | [Domains](domains.md)                           |
| `domains.record_name`                                | `_sso-verification`                             | `SSO_DOMAINS_RECORD_NAME`                     | [Domains](domains.md)                           |
| `domains.refused`                                    | `[]`                                            |                                               | [Domains](domains.md)                           |
| `domains.pending_expiry_seconds`                     | `604800`                                        | `SSO_DOMAINS_PENDING_EXPIRY_SECONDS`          | [Domains](domains.md)                           |
| `domains.recheck_grace_seconds`                      | `259200`                                        | `SSO_DOMAINS_RECHECK_GRACE_SECONDS`           | [Domains](domains.md)                           |
| `domains.linking_max_age_seconds`                    | `86400`                                         | `SSO_DOMAINS_LINKING_MAX_AGE_SECONDS`         | [Domains](domains.md)                           |
| `linking.verified_result_max_age_seconds`            | `120`                                           | `SSO_LINKING_VERIFIED_RESULT_MAX_AGE_SECONDS` | [Provisioning](provisioning.md)                 |
| `linking.evidence_max_age_seconds`                   | `900`                                           | `SSO_LINKING_EVIDENCE_MAX_AGE_SECONDS`        | [Evidence](evidence.md)                         |
| `linking.shared_issuers`                             | `[]`                                            |                                               | [Linking by domain](linking-by-domain.md)       |
| `enforcement.table`                                  | `sso_enforcement`                               | `SSO_ENFORCEMENT_TABLE`                       | [Enforcement](enforcement.md)                   |
| `links.table`                                        | `sso_links`                                     | `SSO_LINKS_TABLE`                             | [Storage](#storage)                             |
| `identity_guards.table`                              | `sso_identity_guards`                           | `SSO_IDENTITY_GUARDS_TABLE`                   | [Storage](#storage)                             |
| `authorization_requests.table`                       | `sso_authorization_requests`                    | `SSO_AUTHORIZATION_REQUESTS_TABLE`            | [Storage](#storage)                             |
| `authorization_requests.ttl_seconds`                 | `600`                                           | `SSO_AUTHORIZATION_REQUESTS_TTL_SECONDS`      | [Flows](#flows)                                 |
| `handoff_codes.table`                                | `sso_handoff_codes`                             | `SSO_HANDOFF_CODES_TABLE`                     | [Storage](#storage)                             |
| `discovery.minimum_duration_milliseconds`            | `250`                                           | `SSO_DISCOVERY_MINIMUM_DURATION_MILLISECONDS` | [Flows](#flows)                                 |
| `mapping.max_value_length`                           | `1024`                                          | `SSO_MAPPING_MAX_VALUE_LENGTH`                | [Managing connections](managing-connections.md) |
| `mapping.max_values`                                 | `100`                                           | `SSO_MAPPING_MAX_VALUES`                      | [Managing connections](managing-connections.md) |
| `mapping.custom_attributes`                          | `[]`                                            |                                               | [Managing connections](managing-connections.md) |
| `freshness.max_age_seconds.<operation>`              | `300` each                                      |                                               | [Fresh authentication](freshness.md)            |
| `single_use.table`                                   | `sso_single_use_keys`                           | `SSO_SINGLE_USE_TABLE`                        | [Single-use keys](single-use-store.md)          |
| `fetcher.timeout_seconds`                            | `10`                                            | `SSO_FETCHER_TIMEOUT_SECONDS`                 | [Outbound requests](outbound-requests.md)       |
| `fetcher.connect_timeout_seconds`                    | `5`                                             | `SSO_FETCHER_CONNECT_TIMEOUT_SECONDS`         | [Outbound requests](outbound-requests.md)       |
| `fetcher.max_response_bytes`                         | `1048576`                                       | `SSO_FETCHER_MAX_RESPONSE_BYTES`              | [Outbound requests](outbound-requests.md)       |
| `fetcher.max_redirects`                              | `3`                                             | `SSO_FETCHER_MAX_REDIRECTS`                   | [Outbound requests](outbound-requests.md)       |
| `fetcher.refused_ranges`                             | `[]`                                            |                                               | [Outbound requests](outbound-requests.md)       |
| `logging.channel`                                    | `null`                                          | `SSO_LOG_CHANNEL`                             | [Logging](logging.md)                           |
| `logging.max_diagnostic_length`                      | `512`                                           | `SSO_LOG_MAX_DIAGNOSTIC_LENGTH`               | [Logging](logging.md)                           |
| `logging.redacted_keys`                              | `[]`                                            |                                               | [Logging](logging.md)                           |
| `rate_limits.table`                                  | `sso_rate_limits`                               | `SSO_RATE_LIMITS_TABLE`                       | [Rate limits](rate-limits.md)                   |
| `rate_limits.connection`                             | `null`                                          | `SSO_RATE_LIMITS_CONNECTION`                  | [Storage](#storage)                             |
| `rate_limits.authorization_request.per_ip`           | 30 per 60 s                                     |                                               | [Rate limits](rate-limits.md)                   |
| `rate_limits.authorization_request.per_email_domain` | 300 per 60 s                                    |                                               | [Rate limits](rate-limits.md)                   |
| `rate_limits.completion.per_ip`                      | 30 per 60 s                                     |                                               | [Rate limits](rate-limits.md)                   |
| `rate_limits.completion.per_connection`              | 600 per 60 s                                    |                                               | [Rate limits](rate-limits.md)                   |
| `rate_limits.redemption.per_ip`                      | 30 per 60 s                                     |                                               | [Rate limits](rate-limits.md)                   |
| `rate_limits.metadata.per_connection`                | 10 per 3600 s                                   |                                               | [Rate limits](rate-limits.md)                   |
| `rate_limits.domain_check.per_connection`            | 30 per 3600 s                                   |                                               | [Rate limits](rate-limits.md)                   |
| `pruning.retention_seconds`                          | `86400`                                         | `SSO_PRUNING_RETENTION_SECONDS`               | [Operations](operations.md)                     |
| `pruning.batch_size`                                 | `1000`                                          | `SSO_PRUNING_BATCH_SIZE`                      | [Operations](operations.md)                     |
| `pruning.max_rows_per_kind`                          | `100000`                                        | `SSO_PRUNING_MAX_ROWS_PER_KIND`               | [Operations](operations.md)                     |
| `operations.cadence.prune`                           | `0 * * * *`                                     | `SSO_OPERATIONS_PRUNE_CADENCE`                | [Operations](operations.md)                     |
| `operations.cadence.domain_recheck`                  | `0 * * * *`                                     | `SSO_OPERATIONS_DOMAIN_RECHECK_CADENCE`       | [Operations](operations.md)                     |
| `operations.cadence.metadata_refresh`                | `*/5 * * * *`                                   | `SSO_OPERATIONS_METADATA_REFRESH_CADENCE`     | [Operations](operations.md)                     |
| `operations.cadence.expiry_report`                   | `0 0 * * *`                                     | `SSO_OPERATIONS_EXPIRY_REPORT_CADENCE`        | [Operations](operations.md)                     |
| `operations.cache_mutexes`                           | `false`                                         | `SSO_OPERATIONS_CACHE_MUTEXES`                | [Operations](operations.md)                     |
| `operations.mutex_minutes`                           | `60`                                            | `SSO_OPERATIONS_MUTEX_MINUTES`                | [Operations](operations.md)                     |

## OIDC limits

Every OpenID Connect connection is held to the caps, windows and timeouts under `oidc`, checked at boot while
`features.oidc` is on (see [Signing In with OIDC](oidc-sign-in.md), [The OIDC Callback](oidc-callback.md) and [Setting
Up An OIDC Connection](oidc-connections.md)). Each has the range given, and a value outside it fails the boot check;
where no default is given, the default is the ceiling:

- an ID token is at most `max_id_token_bytes` (2 KiB to 16 KiB) and is refused before it is read; a JWE, a JSON
  serialisation, a repeated JSON member, `crit` or `b64` is refused whatever its size;
- a JWKS is at most `max_jwks_bytes` (4 KiB to 64 KiB) and `max_jwks_keys` keys (1 to 50), and a discovery document,
  token response and UserInfo response at most their own `max_*_bytes` (4 KiB to 1 MiB, default 64 KiB); the fetcher
  stops reading past the cap;
- a callback is refused before anything in it is read when a parameter repeats or is an array, a name or value is
  longer than `max_callback_parameter_bytes` (256 bytes to 2 KiB), the raw query is longer than
  `max_callback_query_bytes` (1 KiB to 16 KiB, default 8 KiB) or holds more than `max_callback_parameters` (4 to 32,
  default 16) parameters;
- an ID token whose `kid` the stored JWKS lacks refetches it once, at most once per `jwks_refetch_cooldown_seconds` (a
  minute to an hour, default 300) per connection, counted whether the refetch succeeds or not, so a flood of unknown
  `kid`s cannot make the package fetch;
- an ID token's `iat` is at most `id_token_max_age_seconds` old (30 to 3600, default 300), with the clock skew on top;
- a token request and a UserInfo request each take at most `token_timeout_seconds` and `userinfo_timeout_seconds` (1 to
  60, default 10) in place of `fetcher.timeout_seconds`, and are never retried.

The scheduled refresh of a connection's discovery document and JWKS keeps the `metadata` cadence, backoff, claim, queue
and stale limit, each resource counting from its own last validated fetch, whether or not it is scheduled.

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

`features` holds a switch per feature, each `false` by default except `metadata_refresh`, the scheduled refresh, which
is `true`: it has nothing to do until a protocol is on, and turning it off stops the schedule, never the stale limit or
an administrator's refresh. `saml2` and `oidc` turn the protocols on; with neither on the package is not in use, and
nothing but these switches is checked. Every other feature needs a protocol on, and `encrypted_assertions` and
`idp_initiated` need `saml2`. A feature that is on lets an application or a connection opt into it; it never opts in for
them.

Each switch is `true` or `false` (`1` and `0`, as numbers or strings, are read the same). Anything else, a switch the
package does not have (a misspelt one would leave the feature off), or a feature on without the protocol it needs fails
the boot check.

## Endpoints

The package builds each connection's assertion consumer service, OIDC callback, metadata URL, service provider entity id
and public JWKS URL from `endpoints.base_url` and the path pattern of each endpoint, never from the request's host or
headers. It adds no route for any of them. The base URL is an absolute `https` URL (or `http` on `127.0.0.1` or `[::1]`
for development) with no query or fragment, and is required while a protocol is on; it may carry a path prefix. Each
pattern is an absolute path holding `{connection}` once, with no query, fragment, other placeholder or dot segment, and
the patterns differ. Route the same paths to the package's helpers in your application; an application with another
layout binds its own endpoint resolver.

With the defaults and `SSO_BASE_URL=https://api.example.com`, connection `01k...` has its assertion consumer service at
`https://api.example.com/auth/sso/connections/01k.../assertions`, its callback at `.../callback`, its metadata, which is
also its service provider entity id, at `.../metadata`, and its public JWKS, for an OIDC connection using
`private_key_jwt`, at `.../jwks`. To lay the URLs out another way, bind your own `Contracts\EndpointResolver` in a
service provider's `register()`; it is given the connection and answers an `Endpoints\ConnectionEndpoints`, which
refuses anything but an absolute `https` URL (or `http` on a loopback address) with no user information, fragment or
wildcard. This one puts each connection under its own path on the single sign-on host, and a response addressed to any
other URL, the default layout's included, is refused with `recipient_mismatch`:

<!-- snippet: tests/Integration/Examples/Configuration/AppServiceProvider.php#configuration-endpoint-resolver -->

```php
$this->app->scoped(EndpointResolver::class, static fn (): EndpointResolver => new class implements EndpointResolver {
    /**
     * The connection's endpoints, under its own path.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints
     */
    #[\Override]
    public function endpoints(SsoConnection $connection): ConnectionEndpoints
    {
        $base = 'https://sso.example.com/' . rawurlencode($connection->getConnectionId());

        return new ConnectionEndpoints("{$base}/acs", "{$base}/callback", "{$base}/metadata", "{$base}/metadata", "{$base}/jwks");
    }
});
```

## Applications

`applications` registers the applications people sign into through a connection, by a lower-case name: your own front
ends, a fixed set deployed with the code. Each client's connections are rows in the database, not entries here, and
nothing in a request chooses among these values.

<!-- snippet: tests/Integration/Examples/Configuration/config/sso.php#configuration-applications -->

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

A start or a completion names its application, and the package admits it only when it is registered under exactly that
name and the `Contracts\ApplicationPolicy` allows external sign-in; an unknown application and one that does not allow
it are refused alike, with `application_not_allowed`. Bind your own policy to decide from somewhere else; it is given
the registered `Applications\Application` and answers `ExternalSignIn::ALLOWED` or `ExternalSignIn::NOT_ALLOWED`.

The redirect URI a completion goes to is the `Contracts\RedirectUriResolver`'s answer, given the registered application
and the connection the flow went through, never anything from the request. Bind your own to give each client its own
address; an answer that is not an exact redirect URI stops the completion with a `LogicException` rather than
redirecting anywhere. This one sends the `web` application to the host of the client whose connection the flow went
through, read from the application's own record (`ClientHosts`), and every other application to its `redirect_uri`:

<!-- snippet: tests/Integration/Examples/Configuration/AppServiceProvider.php#configuration-redirect-uri-resolver -->

```php
$this->app->singleton(RedirectUriResolver::class, static fn (): RedirectUriResolver => new class implements RedirectUriResolver {
    /**
     * The web application on the host of the connection's client, and
     * every other application on its registered redirect URI.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return string
     */
    #[\Override]
    public function redirectUri(Application $application, SsoConnection $connection): string
    {
        return $application->name === 'web'
            ? 'https://' . ClientHosts::for($connection->getTenantId()) . '/auth/sso/complete'
            : $application->redirectUri;
    }
});
```

The package carries no return URL: keep where the user was going in your client, keyed by the verifier of the flow it
started.

## Flows

An authorisation request waits for its response for `authorization_requests.ttl_seconds`, 60 to 900 seconds (default
600), and is consumed once whether the flow succeeds or fails. A discovery start takes at least
`discovery.minimum_duration_milliseconds`, 50 to 2000 (default 250). This is a timing mitigation, not a guarantee: a
domain that routes to a connection and one that does not answer with the same shape and status, and after the same time
when both finish within the floor, but work that outlasts it (a slow provider or database) still shows. Every start
sleeps out the rest of the floor, so plan worker capacity for it, and raise it if starting a flow through any of your
connections takes longer. Neither can be turned off. A handoff code's lifetime is each application's
`handoff_ttl_seconds`.

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

It prints `[subject] OK`, `[subject] not enabled` for what is off, or one line per problem, and exits `1` when there is
a problem. The subjects are `features` (always checked), `extensions`, `storage`, `endpoints`, `applications`, `clock`,
`secrets`, `fetcher`, `logging`, `rate_limits`, `freshness`, `keys`, `mapping`, `domains`, `flows`, `linking`,
`metadata`, `pruning` and `operations` (each checked while a protocol is on), and `saml2` and `oidc` (each checked while
its protocol is on). The check reads configuration only: it opens no database connection and prints no secret or
configured value. What the checks from `clock` to `operations` cover is in their guides and sections: [Clock](clock.md),
[Secrets](secrets.md), [Outbound requests](outbound-requests.md), [Logging](logging.md), [Rate limits](rate-limits.md),
[Fresh authentication](freshness.md), [Keys and certificates](keys.md), [Managing connections](managing-connections.md),
[Domains](domains.md), [Flows](#flows), [Linking by domain](linking-by-domain.md), [SAML metadata](saml-metadata.md) and
[Operations](operations.md).

### Adding your own checks

An application or a package that composes this one can add its own checks, so a problem in its settings fails the boot,
a worker command and `sso:check` with the package's own. Write a `ConfigurationCheck`: `applies()` says whether what it
covers is on, and `checks()` returns closures, each throwing an exception whose message names one problem and the key,
never the configured value. The check is built before `applies()` is asked, so building it must not depend on what it
covers being on. This one checks the client hosts the redirect URI resolver above reads, and applies only while the
package is in use (`Features::isInUse($config)`, a protocol on in the repository it is given), so an application with
single sign-on off never fails its boot on it. `ClientHostsCheck implements ConfigurationCheck` with these methods:

<!-- snippet: tests/Integration/Examples/Configuration/ClientHostsCheck.php#configuration-added-check -->

```php
/**
 * Constructor.
 *
 * @param  \Illuminate\Contracts\Config\Repository  $config
 */
public function __construct(

    /** The configuration checked. */
    private Repository $config,
) {}

/**
 * Whether the package is in use, so an application with it off never fails
 * its boot on this check.
 *
 * @return bool
 */
#[\Override]
public function applies(): bool
{
    return Features::isInUse($this->config);
}

/**
 * Each client's host must be a non-empty string.
 *
 * @return list<\Closure(): mixed>
 */
#[\Override]
public function checks(): array
{
    return [
        function (): void {
            $hosts = $this->config->get('clients.hosts');

            if (!is_array($hosts) || $hosts === [] || array_filter($hosts, static fn (mixed $host): bool => !is_string($host) || $host === '') !== []) {
                throw new \InvalidArgumentException('`clients.hosts` must give each client a host.');
            }
        },
    ];
}
```

Add it to `ConfigurationChecks` from a service provider's `register()`, through `callAfterResolving()`, which adds it
whichever provider registers first:

<!-- snippet: tests/Integration/Examples/Configuration/AppServiceProvider.php#configuration-add-check -->

```php
$this->callAfterResolving(ConfigurationChecks::class, static function (ConfigurationChecks $checks): void {
    $checks->add('clients', ClientHostsCheck::class);
});
```

An added check runs after the package's own, in the order added, and its problems are listed under its subject, here
`[clients]`. A subject already registered, the package's own included, cannot be added again, and neither can an empty
one: either throws a `LogicException` as the check is added, so an added check never replaces or shadows another. A
class that cannot be built, or is not a `ConfigurationCheck`, is reported as a problem of its subject, as for the
package's own.
