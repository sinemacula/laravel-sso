<?php

declare(strict_types = 1);

return [

    /*
    |---------------------------------------------------------------------------
    | Storage
    |---------------------------------------------------------------------------
    |
    | The connection every package table lives on (`null` for the default),
    | and the rate limit counters too unless `rate_limits.connection` names
    | their own. The models read and write the tables there, and the published
    | migrations create them there. They share one connection because a
    | completion, a redemption, a connection's lifecycle change and a link's
    | activation each write several of them in one transaction, which two
    | connections cannot commit as one; an adapter that must commit with the
    | package (a session revocation, a handoff redeemed by the application's
    | sign-in) writes through this same connection, inside the transaction the
    | package opens. A value that is neither a connection name nor `null` or
    | empty fails closed when a model is built, and `sso:check` reports it, as
    | it does a name `database.connections` does not configure. Keep it fixed
    | while the application runs: moving the tables is a deploy, with a
    | migration the application performs and a worker restart.
    |
    | Each table's name is set in its own section (`connections.table`,
    | `keys.table`, `domains.table`, `enforcement.table`, `links.table`,
    | `authorization_requests.table`, `handoff_codes.table`,
    | `single_use.table`, `rate_limits.table`), each defaulting to an `sso_`
    | prefix.
    |
    */

    'storage' => [
        'connection' => env('SSO_STORAGE_CONNECTION'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Features
    |---------------------------------------------------------------------------
    |
    | Every feature is off until the application turns it on, but for
    | `metadata_refresh`, the scheduled refresh, which is on: it does nothing
    | until a protocol is, and turning it off stops the schedule, never the
    | stale limit. A protocol (`saml2`, `oidc`) is the package in use: with
    | neither on, nothing runs and nothing but these switches is checked.
    | `discovery`, `enforcement`, `domain_linking` and the rest need a protocol
    | on, and `encrypted_assertions` and `idp_initiated` need `saml2`. A
    | feature that is on lets an application or a connection opt into it; it
    | never opts in for them, and the security checks of a feature that is on
    | are always on, with no setting to turn them off.
    |
    | Each switch is true or false (`1` and `0` are read the same); anything
    | else, or a switch the package does not have, fails the boot check.
    |
    */

    'features' => [
        'saml2'                => env('SSO_SAML2', false),
        'oidc'                 => env('SSO_OIDC', false),
        'discovery'            => env('SSO_DISCOVERY', false),
        'enforcement'          => env('SSO_ENFORCEMENT', false),
        'encrypted_assertions' => env('SSO_ENCRYPTED_ASSERTIONS', false),
        'metadata_refresh'     => env('SSO_METADATA_REFRESH', true),
        'idp_initiated'        => env('SSO_IDP_INITIATED', false),
        'domain_linking'       => env('SSO_DOMAIN_LINKING', false),
    ],

    /*
    |---------------------------------------------------------------------------
    | Endpoints
    |---------------------------------------------------------------------------
    |
    | What the default endpoint resolver builds each connection's assertion
    | consumer service, OIDC callback, metadata URL, service provider entity
    | id and public JWKS URL from: the base URL (`https`, or `http` on
    | 127.0.0.1 or [::1] for development; no query or fragment) and a path
    | pattern holding `{connection}` once. Nothing is ever built from the
    | request's host or headers. Required while a protocol is on; an
    | application with another layout binds its own resolver. The package adds
    | no route: the application serves these URLs, the JWKS URL with the body
    | `ServiceProviderDescriptions::publicKeys()` answers.
    |
    */

    'endpoints' => [
        'base_url' => env('SSO_BASE_URL'),

        'paths' => [
            'assertion_consumer_service' => '/auth/sso/connections/{connection}/assertions',
            'callback'                   => '/auth/sso/connections/{connection}/callback',
            'metadata'                   => '/auth/sso/connections/{connection}/metadata',
            'jwks'                       => '/auth/sso/connections/{connection}/jwks',
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Applications
    |---------------------------------------------------------------------------
    |
    | The applications people sign into through a connection (the suite's own
    | front ends, web and mobile), a fixed set deployed with the code, by a
    | lower-case name. Each client's connections are rows in the database, not
    | entries here. Nothing in a request chooses among these values.
    |
    | - `redirect_uri`: required. The one URI the completion redirects to,
    |   compared as an exact string, with no wildcard, pattern or added path:
    |   `https`, `http` on a loopback address, or a private-use scheme a native
    |   application registers (`com.example.app:/sso`). The exact URI is
    |   answered by the `RedirectUriResolver` contract, which defaults to this
    |   setting; bind your own to answer a per-client address without a schema
    |   change.
    | - `external_sign_in`: whether the application allows sign-in through an
    |   external provider (default false). Under `laravel-iam` the answer comes
    |   from `laravel-authentication`'s per-application methods instead.
    | - `delivery`: where the handoff code goes on the redirect URI, the
    |   `fragment` (default) or the `query`.
    | - `discovery`: whether the application offers discovery by email domain
    |   (`enabled`, default false, and only while the `discovery` feature is
    |   on) and the `fallback_url` a miss leads to, required while it does.
    | - `unlinked_handoffs`: whether a sign-in that resolves to no identity is
    |   still handed off, for an application that resolves identities itself
    |   on redemption (default false).
    | - `handoff_ttl_seconds`: the handoff code's lifetime, 1 to 300 (default
    |   60).
    |
    | An application named `web` that allows external sign-in and takes every
    | other default is `'web' => ['redirect_uri' => '<its URI>',
    | 'external_sign_in' => true]`. The start URL an unsolicited SAML response
    | is sent to for re-initiation is a connection's setting, since such a
    | response names no application.
    |
    */

    'applications' => [],

    /*
    |---------------------------------------------------------------------------
    | Clock
    |---------------------------------------------------------------------------
    |
    | The clock skew, in seconds (0 to 300), every protocol time check allows
    | (SAML `NotBefore` and `NotOnOrAfter`, OIDC `exp`, `iat` and `auth_time`).
    | Every time check reads the one bindable clock.
    |
    */

    'clock' => [
        'skew_seconds' => env('SSO_CLOCK_SKEW_SECONDS', 60),
    ],

    /*
    |---------------------------------------------------------------------------
    | SAML 2.0
    |---------------------------------------------------------------------------
    |
    | The caps and windows every SAML connection is held to; every check is
    | always on. A posted `SAMLResponse` longer than `max_response_bytes` is
    | refused before it is decoded (16 KiB to 1 MiB, default 256 KiB), a
    | decoded one longer than `max_xml_bytes` before it is parsed (16 KiB to
    | 1 MiB, default 192 KiB), and an assertion decrypted from an
    | `EncryptedAssertion` longer than `max_decrypted_bytes` before it is
    | parsed (4 KiB to 1 MiB, default 128 KiB). A response's and an assertion's
    | `IssueInstant` may be at most `issue_instant_max_age_seconds` old (30 to
    | 3600, default 300), with the clock skew on top.
    |
    */

    'saml2' => [
        'max_response_bytes'            => env('SSO_SAML2_MAX_RESPONSE_BYTES', 262144),
        'max_xml_bytes'                 => env('SSO_SAML2_MAX_XML_BYTES', 196608),
        'max_decrypted_bytes'           => env('SSO_SAML2_MAX_DECRYPTED_BYTES', 131072),
        'issue_instant_max_age_seconds' => env('SSO_SAML2_ISSUE_INSTANT_MAX_AGE_SECONDS', 300),
    ],

    /*
    |---------------------------------------------------------------------------
    | OpenID Connect
    |---------------------------------------------------------------------------
    |
    | The caps, windows and timeouts every OIDC connection is held to; every
    | check is always on, and a cap can be lowered, never raised past its
    | ceiling. An ID token longer than `max_id_token_bytes` (2 KiB to 16 KiB,
    | default 16 KiB) is refused before it is read. A JWKS larger than
    | `max_jwks_bytes` (4 KiB to 64 KiB, default 64 KiB) or holding more than
    | `max_jwks_keys` keys (1 to 50, default 50) is refused whole. A discovery
    | document, token response or UserInfo response larger than its
    | `max_*_bytes` (4 KiB to 1 MiB, default 64 KiB) fails as it arrives.
    |
    | A callback is refused before anything in it is read when a parameter is
    | repeated or given as an array, when a name or value is longer than
    | `max_callback_parameter_bytes` (256 bytes to 2 KiB, default 2 KiB), when
    | the raw query is longer than `max_callback_query_bytes` (1 KiB to 16 KiB,
    | default 8 KiB), or when it holds more than `max_callback_parameters`
    | parameters (4 to 32, default 16).
    |
    | An ID token whose `kid` the stored JWKS does not hold refetches the JWKS
    | once, at most once per `jwks_refetch_cooldown_seconds` per connection (a
    | minute to an hour, default 300), whether the refetch succeeds or not, so
    | a flood of unknown `kid`s cannot make the package fetch. An ID token's
    | `iat` may be at most `id_token_max_age_seconds` old (30 to 3600, default
    | 300), with the clock skew on top. A token request and a UserInfo request
    | each take at most `token_timeout_seconds` and `userinfo_timeout_seconds`
    | (1 to 60, default 10) and are never retried.
    |
    | The scheduled refresh of a connection's discovery document and JWKS
    | follows the `metadata` section's cadence, backoff, claim, queue and stale
    | limit.
    |
    */

    'oidc' => [
        'max_id_token_bytes'            => env('SSO_OIDC_MAX_ID_TOKEN_BYTES', 16384),
        'max_jwks_bytes'                => env('SSO_OIDC_MAX_JWKS_BYTES', 65536),
        'max_jwks_keys'                 => env('SSO_OIDC_MAX_JWKS_KEYS', 50),
        'max_discovery_bytes'           => env('SSO_OIDC_MAX_DISCOVERY_BYTES', 65536),
        'max_token_response_bytes'      => env('SSO_OIDC_MAX_TOKEN_RESPONSE_BYTES', 65536),
        'max_userinfo_bytes'            => env('SSO_OIDC_MAX_USERINFO_BYTES', 65536),
        'max_callback_parameter_bytes'  => env('SSO_OIDC_MAX_CALLBACK_PARAMETER_BYTES', 2048),
        'max_callback_query_bytes'      => env('SSO_OIDC_MAX_CALLBACK_QUERY_BYTES', 8192),
        'max_callback_parameters'       => env('SSO_OIDC_MAX_CALLBACK_PARAMETERS', 16),
        'jwks_refetch_cooldown_seconds' => env('SSO_OIDC_JWKS_REFETCH_COOLDOWN_SECONDS', 300),
        'id_token_max_age_seconds'      => env('SSO_OIDC_ID_TOKEN_MAX_AGE_SECONDS', 300),
        'token_timeout_seconds'         => env('SSO_OIDC_TOKEN_TIMEOUT_SECONDS', 10),
        'userinfo_timeout_seconds'      => env('SSO_OIDC_USERINFO_TIMEOUT_SECONDS', 10),
    ],

    /*
    |---------------------------------------------------------------------------
    | Metadata
    |---------------------------------------------------------------------------
    |
    | How large a SAML identity provider's metadata may be, imported or
    | refreshed, given as XML or fetched: `max_bytes`, 64 KiB to a hard ceiling
    | of 256 MiB (default 1 MiB), in place of `fetcher.max_response_bytes`,
    | which every other request keeps. A fetch stops reading past it and a
    | document over it is never parsed. Raising it for a federation aggregate
    | means the whole file is loaded and its signature checked in one piece:
    | expect memory of several times the file's size and seconds of
    | processing, and size the queue worker's memory limit and `timeout_seconds`
    | for it. Where the federation publishes a URL per entity, use that
    | instead. An import from a URL fetches while it is called, so import a
    | large aggregate from the console or a queued job, never a web request.
    |
    | How the scheduled refresh runs of a SAML connection's metadata, and of an
    | OIDC connection's discovery document and JWKS, while
    | `features.metadata_refresh` is on: every OIDC connection refreshes unless
    | its `metadata_refresh` setting is off, and a SAML connection with a
    | `metadata_url` refreshes when its setting is `true`, or is unset and it
    | has a metadata signing anchor. After a success the next refresh is due
    | `refresh_interval_seconds` later (an hour to a week, default a day);
    | after a failure it waits `backoff_initial_seconds` (a minute to an hour,
    | default 5 minutes), doubling with each failure in a row up to
    | `backoff_max_seconds` (5 minutes to a day, default 6 hours).
    |
    | Whatever was fetched and validated stops being used `stale_limit_seconds`
    | after its own last validated fetch (a day to a year, default 30 days, or
    | 0 for no limit, which you must set explicitly), or at its metadata's
    | `validUntil`, whichever comes first, scheduled or not: turning the
    | schedule off never means unlimited trust. An expired connection recovers
    | through the schedule or an administrator's refresh, never by itself.
    | Settings saved from a fetched import count from that fetch. Settings and
    | keys saved by hand, with nothing fetched, have no deadline.
    | A server's claim on a refresh holds for `claim_seconds` (30 to 3600,
    | default 300), so racing servers refresh a connection once. Run the
    | refresh command more often than the initial backoff.
    |
    | The command queues one job per connection due (`--sync` refreshes them
    | in the command instead): on `queue.connection` and `queue.name` (`null`
    | for the application's default connection and its default queue), each
    | allowed `queue.timeout_seconds` (30 to 3600, default 60, at most
    | `claim_seconds`) and `queue.tries` attempts (1 to 10, default 1; a failed
    | refresh is retried by the backoff). The timeout must be shorter than the
    | queue connection's `retry_after` (90 in Laravel's stock queue config),
    | or a refresh still running is reserved by a second worker and recorded
    | as failed; the boot check refuses one that is not. Send large aggregates
    | to a queue whose workers have the memory and the timeout for them, and
    | raise that connection's `retry_after` above the timeout.
    |
    */

    'metadata' => [
        'max_bytes'                => env('SSO_METADATA_MAX_BYTES', 1048576),
        'refresh_interval_seconds' => env('SSO_METADATA_REFRESH_INTERVAL_SECONDS', 86400),
        'backoff_initial_seconds'  => env('SSO_METADATA_BACKOFF_INITIAL_SECONDS', 300),
        'backoff_max_seconds'      => env('SSO_METADATA_BACKOFF_MAX_SECONDS', 21600),
        'stale_limit_seconds'      => env('SSO_METADATA_STALE_LIMIT_SECONDS', 2592000),
        'claim_seconds'            => env('SSO_METADATA_CLAIM_SECONDS', 300),

        'queue' => [
            'connection'      => env('SSO_METADATA_QUEUE_CONNECTION'),
            'name'            => env('SSO_METADATA_QUEUE'),
            'timeout_seconds' => env('SSO_METADATA_QUEUE_TIMEOUT_SECONDS', 60),
            'tries'           => env('SSO_METADATA_QUEUE_TRIES', 1),
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Connections
    |---------------------------------------------------------------------------
    |
    | The table each tenant's connections are kept in, on the storage
    | connection: one row per trust in one identity provider over one
    | protocol, with its settings, its secrets (encrypted), its attribute
    | mapping and whether it is enabled. Connections are rows, managed through
    | the package's helpers, never entries here.
    |
    */

    'connections' => [
        'table' => env('SSO_CONNECTIONS_TABLE', 'sso_connections'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Keys and certificates
    |---------------------------------------------------------------------------
    |
    | The table each connection's own key pairs and trusted identity provider
    | certificates are kept in, on the storage connection, and how the package
    | generates and rotates its keys. A generated RSA key has a modulus of
    | `rsa_bits`, 3072 or 4096 bits, and an elliptic curve key is always on
    | P-256. A generated self-signed certificate is valid for
    | `certificate_days`, from one day to ten years; its dates are reported,
    | never enforced. A key replaced as current is still accepted for
    | decryption for `overlap_seconds`, from none to 90 days. A certificate's
    | expiry is reported as near `expiry_warning_days` ahead, from one day to
    | a year.
    |
    */

    'keys' => [
        'table'               => env('SSO_KEYS_TABLE', 'sso_keys'),
        'rsa_bits'            => env('SSO_KEYS_RSA_BITS', 3072),
        'certificate_days'    => env('SSO_KEYS_CERTIFICATE_DAYS', 730),
        'overlap_seconds'     => env('SSO_KEYS_OVERLAP_SECONDS', 604800),
        'expiry_warning_days' => env('SSO_KEYS_EXPIRY_WARNING_DAYS', 30),
    ],

    /*
    |---------------------------------------------------------------------------
    | Attribute mapping
    |---------------------------------------------------------------------------
    |
    | The caps on what a connection's attribute mapping carries. Mapped values
    | are profile data, never used to select an identity: the longest value
    | kept (`max_value_length`, 64 to 65535 characters), the most values one
    | attribute keeps (`max_values`, 1 to 10000, a list of groups say), and the
    | most custom keys a mapping may declare (`max_custom_attributes`, 0 to
    | 100).
    |
    */

    'mapping' => [
        'max_value_length'      => env('SSO_MAPPING_MAX_VALUE_LENGTH', 1024),
        'max_values'            => env('SSO_MAPPING_MAX_VALUES', 100),
        'max_custom_attributes' => env('SSO_MAPPING_MAX_CUSTOM_ATTRIBUTES', 20),
    ],

    /*
    |---------------------------------------------------------------------------
    | Domains
    |---------------------------------------------------------------------------
    |
    | The table each connection's claimed email domains are kept in, on the
    | storage connection, and how a claim is verified and kept verified. A
    | domain is claimed exactly as given (a verified domain covers none of its
    | subdomains), pending until a DNS TXT record at `record_name` under it
    | (`_sso-verification.example.com`) carries the claim's token, and verified
    | for at most one connection at a time.
    |
    | - `record_name`: the name the TXT record is looked up at under the
    |   domain, one to four labels of lower-case letters, digits, `-` and `_`,
    |   at most 63 characters. Each claim keeps the name it was made with, so
    |   changing it affects new claims only.
    | - `refused`: domains no tenant may claim, added to the public mailbox
    |   providers the package always refuses (`gmail.com`, `outlook.com` and
    |   the like); it never removes one. A listed domain's subdomains are
    |   refused too.
    | - `pending_expiry_seconds`: how long a claim waits to be verified, an
    |   hour to 30 days (default 7 days). An expired claim is claimed again
    |   for a new token.
    | - `recheck_grace_seconds`: how long a verified domain whose record has
    |   gone keeps routing discovery before it lapses, none to 30 days (default
    |   3 days). Linking by the domain stops at once.
    | - `linking_max_age_seconds`: how recent a domain's last successful check
    |   must be for it to allow linking by email, 60 seconds to 24 hours, the
    |   default and the ceiling, so a stopped scheduler cannot extend it.
    |
    */

    'domains' => [
        'table'                   => env('SSO_DOMAINS_TABLE', 'sso_domains'),
        'record_name'             => env('SSO_DOMAINS_RECORD_NAME', '_sso-verification'),
        'refused'                 => [],
        'pending_expiry_seconds'  => env('SSO_DOMAINS_PENDING_EXPIRY_SECONDS', 604800),
        'recheck_grace_seconds'   => env('SSO_DOMAINS_RECHECK_GRACE_SECONDS', 259200),
        'linking_max_age_seconds' => env('SSO_DOMAINS_LINKING_MAX_AGE_SECONDS', 86400),
    ],

    /*
    |---------------------------------------------------------------------------
    | Enforcement
    |---------------------------------------------------------------------------
    |
    | The table each tenant's enforcement is kept in, on the storage
    | connection: whether sessions active in the tenant must be established
    | through one of its own connections, which connections satisfy it, and
    | the version that changes with every change. Enforcement is off for every
    | tenant until `features.enforcement` is on and a tenant turns it on.
    |
    */

    'enforcement' => [
        'table' => env('SSO_ENFORCEMENT_TABLE', 'sso_enforcement'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Links
    |---------------------------------------------------------------------------
    |
    | The table links are kept in, on the storage connection: each
    | connection's issuer and subject (stored byte for byte) associated with
    | an identity, unique on the connection, issuer and subject. How many links
    | an identity may hold in one connection is the `LinkLimit` contract's
    | answer, one by default.
    |
    */

    'links' => [
        'table' => env('SSO_LINKS_TABLE', 'sso_links'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Authorisation requests
    |---------------------------------------------------------------------------
    |
    | The table each attempt at a flow is kept in, on the storage connection,
    | until its response consumes it, and how long it waits for that response:
    | `ttl_seconds`, 60 to 900 seconds (default 600). Its protocol state and
    | nonce are kept only as digests, and the PKCE verifier the package uses
    | with the identity provider only encrypted.
    |
    */

    'authorization_requests' => [
        'table'       => env('SSO_AUTHORIZATION_REQUESTS_TABLE', 'sso_authorization_requests'),
        'ttl_seconds' => env('SSO_AUTHORIZATION_REQUESTS_TTL_SECONDS', 600),
    ],

    /*
    |---------------------------------------------------------------------------
    | Handoff codes
    |---------------------------------------------------------------------------
    |
    | The table the package's own handoff store keeps its codes in, on the
    | storage connection, each only as a digest, with the verified result it
    | carries encrypted. A code's lifetime is each application's
    | `handoff_ttl_seconds`.
    |
    */

    'handoff_codes' => [
        'table' => env('SSO_HANDOFF_CODES_TABLE', 'sso_handoff_codes'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Discovery
    |---------------------------------------------------------------------------
    |
    | The least time a discovery start takes, in milliseconds (50 to 2000,
    | default 250): a timing mitigation, so a domain that routes to a
    | connection and one that does not answer after the same time when both
    | finish within it. Work that outlasts it (a slow provider or database)
    | still shows. Every start sleeps out the rest of it, so plan worker
    | capacity for it. It cannot be turned off; raise it if starting a flow
    | through any of your connections takes longer.
    |
    */

    'discovery' => [
        'minimum_duration_milliseconds' => env('SSO_DISCOVERY_MINIMUM_DURATION_MILLISECONDS', 250),
    ],

    /*
    |---------------------------------------------------------------------------
    | Fresh authentication
    |---------------------------------------------------------------------------
    |
    | Before each operation that could widen or redirect access, or destroy
    | it, the package asks the bound freshness contract whether the caller
    | authenticated within the operation's maximum age, in seconds (1 to
    | 3600). The default contract refuses every operation: bind your own, or
    | let `laravel-iam` bind `laravel-authentication`'s, before using the
    | management helpers. Each key is the operation's stable name after `sso.`,
    | with the dots as underscores (`sso.connection.trust` is
    | `connection_trust`).
    |
    */

    'freshness' => [
        'max_age_seconds' => [
            'connection_trust'         => 300,
            'connection_enable'        => 300,
            'connection_disable'       => 300,
            'connection_delete'        => 300,
            'connection_idp_initiated' => 300,
            'keys_rotate'              => 300,
            'domain_claim'             => 300,
            'domain_verify'            => 300,
            'domain_remove'            => 300,
            'enforcement_update'       => 300,
            'link_create'              => 300,
            'link_remove'              => 300,
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Single-use keys
    |---------------------------------------------------------------------------
    |
    | The table the default single-use store records assertion ids,
    | authorisation requests and handoff codes in, on the storage connection,
    | each until its expiry, under a unique index.
    |
    */

    'single_use' => [
        'table' => env('SSO_SINGLE_USE_TABLE', 'sso_single_use_keys'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Outbound requests
    |---------------------------------------------------------------------------
    |
    | Every request to an identity provider (metadata, discovery, JWKS, token
    | and UserInfo) goes through one fetcher: `https` only, to a checked
    | address that is never loopback, private, link-local, unique-local,
    | multicast or a cloud metadata address, pinned so a second resolution
    | cannot change it. `refused_ranges` adds CIDR ranges (IPv4 or IPv6) to the
    | ones always refused; it never removes one. A response larger than
    | `max_response_bytes` (SAML metadata has its own cap,
    | `metadata.max_bytes`) or slower than `timeout_seconds` fails, and a
    | request that carries no credential follows at most `max_redirects`
    | redirects, each checked again (one that carries a credential follows
    | none).
    |
    */

    'fetcher' => [
        'timeout_seconds'         => env('SSO_FETCHER_TIMEOUT_SECONDS', 10),
        'connect_timeout_seconds' => env('SSO_FETCHER_CONNECT_TIMEOUT_SECONDS', 5),
        'max_response_bytes'      => env('SSO_FETCHER_MAX_RESPONSE_BYTES', 1048576),
        'max_redirects'           => env('SSO_FETCHER_MAX_REDIRECTS', 3),
        'refused_ranges'          => [],
    ],

    /*
    |---------------------------------------------------------------------------
    | Logging
    |---------------------------------------------------------------------------
    |
    | Where the package logs (`null` for the default channel), and how much of
    | an identity provider's diagnostic text it keeps: at most
    | `max_diagnostic_length` characters (64 to 4096), with control characters
    | removed. Verifiers, handoff codes, protocol state, assertions, provider
    | tokens and secrets are always redacted from every log call and its
    | context; `redacted_keys` adds key names to redact, never removes one.
    |
    */

    'logging' => [
        'channel'               => env('SSO_LOG_CHANNEL'),
        'max_diagnostic_length' => env('SSO_LOG_MAX_DIAGNOSTIC_LENGTH', 512),
        'redacted_keys'         => [],
    ],

    /*
    |---------------------------------------------------------------------------
    | Rate limits
    |---------------------------------------------------------------------------
    |
    | Limits on each flow, counted in `table` on `connection` (`null` for the
    | storage connection), so they hold across servers without a cache. Each is
    | `max` attempts (1 to 1000000) per window of `decay_seconds` (1 to 86400).
    | Every limit is always on: a missing or malformed one fails the boot
    | check, never turns the limit off. Every attempt counts, successful or
    | not, and a full limit refuses with the seconds until its window ends.
    |
    */

    'rate_limits' => [
        'table'      => env('SSO_RATE_LIMITS_TABLE', 'sso_rate_limits'),
        'connection' => env('SSO_RATE_LIMITS_CONNECTION'),

        'authorization_request' => [
            'per_ip'           => ['max' => 30, 'decay_seconds' => 60],
            'per_email_domain' => ['max' => 300, 'decay_seconds' => 60],
        ],

        'completion' => [
            'per_ip'         => ['max' => 30, 'decay_seconds' => 60],
            'per_connection' => ['max' => 600, 'decay_seconds' => 60],
        ],

        'redemption' => [
            'per_ip' => ['max' => 30, 'decay_seconds' => 60],
        ],

        'metadata' => [
            'per_connection' => ['max' => 10, 'decay_seconds' => 3600],
        ],

        'domain_check' => [
            'per_connection' => ['max' => 30, 'decay_seconds' => 3600],
        ],
    ],
];
