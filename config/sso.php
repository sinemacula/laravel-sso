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
    | their own. The tables share one connection because several flows write
    | more than one of them in a single transaction. A name that is not
    | configured fails closed and `sso:check` reports it. Keep it fixed while
    | the application runs: moving the tables is a deploy, with a migration
    | and a worker restart. Each table's name is set in its own section.
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
    | Every feature is off by default except `metadata_refresh`, which does
    | nothing until a protocol is on. `saml2` and `oidc` are the protocols;
    | every other feature needs one, and `encrypted_assertions` and
    | `idp_initiated` need `saml2`. A feature that is on lets an application
    | or connection opt in, and its security checks cannot be turned off.
    | Each switch is true or false (`1` and `0` too); anything else, or an
    | unknown switch, fails the boot check.
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
    | The base URL and path patterns each connection's service provider URLs
    | are built from, never the request's host or headers. The base URL is
    | `https` (or `http` on 127.0.0.1 or [::1]) with no query or fragment, and
    | is required while a protocol is on. Each path holds `{connection}` once.
    | The package adds no routes: the application serves these URLs.
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
    | The applications people sign into through a connection, by lower-case
    | name: a fixed set deployed with the code. Each needs a `redirect_uri`,
    | matched exactly (`https`, `http` on a loopback address, or a native
    | application's private-use scheme), and may set `external_sign_in`
    | (default false), `delivery` (`fragment` or `query`), `discovery`
    | (`enabled` and `fallback_url`), `unlinked_handoffs` (default false) and
    | `handoff_ttl_seconds` (1 to 300, default 60). For example:
    | `'web' => ['redirect_uri' => '<its URI>', 'external_sign_in' => true]`.
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
    | The size caps and `IssueInstant` window every SAML response is held to;
    | each check is always on. Sizes are in bytes: `max_response_bytes` for
    | the posted response and `max_xml_bytes` once decoded (16 KiB to 1 MiB
    | each), and `max_decrypted_bytes` for a decrypted assertion (4 KiB to
    | 1 MiB). `issue_instant_max_age_seconds` is 30 to 3600, plus the skew.
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
    | The size caps, windows and timeouts every OIDC connection is held to;
    | each check is always on, and a cap can be lowered but never raised past
    | its ceiling. Sizes are in bytes and times in seconds. An unknown `kid`
    | refetches the JWKS at most once per `jwks_refetch_cooldown_seconds` per
    | connection. Token and UserInfo requests are never retried. The scheduled
    | refresh of discovery documents and JWKS follows the `metadata` section.
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
    | The SAML metadata size cap, and how the scheduled refresh of SAML
    | metadata and OIDC discovery documents and JWKS runs. `max_bytes` (64 KiB
    | to 256 MiB) replaces `fetcher.max_response_bytes` for SAML metadata; a
    | federation aggregate needs worker memory and a timeout to match, so
    | import one from the console or a queued job, never a web request.
    |
    | Times are in seconds. Fetched metadata stops being trusted
    | `stale_limit_seconds` after its last validated fetch (0 for no limit,
    | set explicitly), even with the schedule off. Run the refresh command
    | more often than `backoff_initial_seconds`. `queue.timeout_seconds` must
    | be below the queue connection's `retry_after`; the boot check refuses
    | one that is not.
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
    | The table connections are kept in: one row per trust in an identity
    | provider over one protocol, with its secrets encrypted. Connections are
    | managed through the package's helpers, never configured here.
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
    | The table connection key pairs and trusted certificates are kept in, and
    | how keys are generated and rotated. `rsa_bits` is 3072 or 4096 (EC keys
    | are P-256), `certificate_days` 1 to 3650 (reported, never enforced),
    | and `overlap_seconds` how long a replaced key still decrypts, up to 90
    | days. `expiry_thresholds` are the days before expiry
    | `sso:keys:expiring` warns at, 0 to 365 and always including 0.
    |
    */

    'keys' => [
        'table'                => env('SSO_KEYS_TABLE', 'sso_keys'),
        'rsa_bits'             => env('SSO_KEYS_RSA_BITS', 3072),
        'certificate_days'     => env('SSO_KEYS_CERTIFICATE_DAYS', 730),
        'overlap_seconds'      => env('SSO_KEYS_OVERLAP_SECONDS', 604800),
        'expiry_thresholds'    => [30, 14, 7, 1, 0],
        'expiry_claim_seconds' => env('SSO_KEYS_EXPIRY_CLAIM_SECONDS', 300),
    ],

    /*
    |---------------------------------------------------------------------------
    | Attribute mapping
    |---------------------------------------------------------------------------
    |
    | Limits on a connection's attribute mapping, whose values are profile
    | data and never select an identity. `max_value_length` is in characters
    | (64 to 65535) and `max_values` caps one attribute's values (1 to 10000).
    | `custom_attributes` lists up to 100 extra keys your application reads,
    | each a lower-case letter then up to 63 lower-case letters, digits or
    | underscores.
    |
    */

    'mapping' => [
        'max_value_length'  => env('SSO_MAPPING_MAX_VALUE_LENGTH', 1024),
        'max_values'        => env('SSO_MAPPING_MAX_VALUES', 100),
        'custom_attributes' => [],
    ],

    /*
    |---------------------------------------------------------------------------
    | Domains
    |---------------------------------------------------------------------------
    |
    | The table claimed email domains are kept in, and how a claim is
    | verified: by a DNS TXT record at `record_name` under the domain
    | (`_sso-verification.example.com`); changing it affects new claims only.
    | A verified domain covers none of its subdomains. `refused` adds to the
    | public mailbox domains the package always refuses. Times are in
    | seconds; `linking_max_age_seconds` is at most a day.
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
    | The table each tenant's enforcement is kept in. Enforcement is off for
    | every tenant until `features.enforcement` is on and the tenant turns it
    | on.
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
    | The table linking a connection's issuer and subject to an identity. How
    | many links an identity may hold per connection is the `LinkLimit`
    | contract's answer, one by default.
    |
    */

    'links' => [
        'table' => env('SSO_LINKS_TABLE', 'sso_links'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Identity guards
    |---------------------------------------------------------------------------
    |
    | The table of per-identity lock rows that serialise linking changes for
    | an identity.
    |
    */

    'identity_guards' => [
        'table' => env('SSO_IDENTITY_GUARDS_TABLE', 'sso_identity_guards'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Linking, provisioning and evidence
    |---------------------------------------------------------------------------
    |
    | How long a verified response may keep finishing across a provisioning
    | listener (5 to 300 seconds), and the longest time since the provider's
    | authentication a connection's evidence is accepted (60 to 3600 seconds;
    | a connection may only tighten it). `shared_issuers` maps issuers shared
    | by many organisations to the claim naming the organisation, adding to
    | those the package knows.
    |
    */

    'linking' => [
        'verified_result_max_age_seconds' => env('SSO_LINKING_VERIFIED_RESULT_MAX_AGE_SECONDS', 120),
        'evidence_max_age_seconds'        => env('SSO_LINKING_EVIDENCE_MAX_AGE_SECONDS', 900),
        'shared_issuers'                  => [],
    ],

    /*
    |---------------------------------------------------------------------------
    | Authorisation requests
    |---------------------------------------------------------------------------
    |
    | The table each flow attempt is kept in until its response consumes it,
    | and how long it waits for that response, in seconds (60 to 900).
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
    | The table the default handoff store keeps its codes in. A code's
    | lifetime is each application's `handoff_ttl_seconds`.
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
    | The least time a discovery start takes, in milliseconds (50 to 2000),
    | so a domain that routes to a connection and one that does not answer
    | alike. Every start sleeps out the rest, so plan worker capacity for it,
    | and raise it if starting a flow through any connection takes longer. It
    | cannot be turned off.
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
    | How recently, in seconds (1 to 3600), the caller must have authenticated
    | before each sensitive management operation. The default freshness
    | contract refuses every operation: bind your own, or let an adapter bind
    | one, before using the management helpers. Each key is the operation's
    | name after `sso.` with dots as underscores.
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
    | The table the default single-use store records consumed assertion ids,
    | authorisation requests and handoff codes in until each expires.
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
    | Every request to an identity provider goes through one fetcher: `https`
    | only, to a pinned public address (never loopback, private, link-local,
    | multicast or a cloud metadata address). `refused_ranges` adds CIDR
    | ranges to those always refused. Times are in seconds and sizes in
    | bytes; SAML metadata uses `metadata.max_bytes` instead. A request that
    | carries a credential follows no redirects.
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
    | The log channel (`null` for the default) and the longest provider
    | diagnostic text kept, in characters (64 to 4096). Secrets, tokens,
    | codes and protocol state are always redacted; `redacted_keys` adds key
    | names to redact.
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
    | storage connection) so they hold across servers without a cache. Each
    | is `max` attempts (1 to 1000000) per `decay_seconds` (1 to 86400). Every
    | limit is always on: a missing or malformed one fails the boot check.
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

    /*
    |---------------------------------------------------------------------------
    | Pruning
    |---------------------------------------------------------------------------
    |
    | What `sso:prune` keeps and how much it does at a time. Authorisation
    | requests and handoff codes are kept `retention_seconds` (0 to 90 days)
    | past expiry for diagnosis; everything else goes when it expires.
    | `batch_size` caps the rows per statement and `max_rows_per_kind` the
    | rows of each kind per run; `sso:prune --drain` goes past it.
    |
    */

    'pruning' => [
        'retention_seconds' => env('SSO_PRUNING_RETENTION_SECONDS', 86400),
        'batch_size'        => env('SSO_PRUNING_BATCH_SIZE', 1000),
        'max_rows_per_kind' => env('SSO_PRUNING_MAX_ROWS_PER_KIND', 100000),
    ],

    /*
    |---------------------------------------------------------------------------
    | Operations
    |---------------------------------------------------------------------------
    |
    | What `Operations\OperationsSchedule` registers: each command's cron
    | cadence, or `null` or empty to schedule it yourself. Every command is
    | safe to run on several servers at once. `cache_mutexes` opts in to
    | `withoutOverlapping()` and `onOneServer()`, which need a cache every
    | server shares; a mutex a dead process leaves behind blocks that command
    | for `mutex_minutes` (1 to 1440).
    |
    */

    'operations' => [
        'cadence' => [
            'prune'            => env('SSO_OPERATIONS_PRUNE_CADENCE', '0 * * * *'),
            'domain_recheck'   => env('SSO_OPERATIONS_DOMAIN_RECHECK_CADENCE', '0 * * * *'),
            'metadata_refresh' => env('SSO_OPERATIONS_METADATA_REFRESH_CADENCE', '*/5 * * * *'),
            'expiry_report'    => env('SSO_OPERATIONS_EXPIRY_REPORT_CADENCE', '0 0 * * *'),
        ],

        'cache_mutexes' => env('SSO_OPERATIONS_CACHE_MUTEXES', false),
        'mutex_minutes' => env('SSO_OPERATIONS_MUTEX_MINUTES', 60),
    ],
];
