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
    | `keys.table`, `single_use.table`, `rate_limits.table`), each defaulting
    | to an `sso_` prefix.
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
    | Every feature is off until the application turns it on. A protocol
    | (`saml2`, `oidc`) is the package in use: with neither on, nothing runs
    | and nothing but these switches is checked. Every other feature needs a
    | protocol on, and `encrypted_assertions` and `idp_initiated` need `saml2`.
    | A feature that is on lets an application or a connection opt into it; it
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
        'metadata_refresh'     => env('SSO_METADATA_REFRESH', false),
        'idp_initiated'        => env('SSO_IDP_INITIATED', false),
        'domain_linking'       => env('SSO_DOMAIN_LINKING', false),
    ],

    /*
    |---------------------------------------------------------------------------
    | Endpoints
    |---------------------------------------------------------------------------
    |
    | What the default endpoint resolver builds each connection's assertion
    | consumer service, OIDC callback, metadata URL and service provider
    | entity id from: the base URL (`https`, or `http` on 127.0.0.1 or [::1]
    | for development; no query or fragment) and a path pattern holding
    | `{connection}` once. Nothing is ever built from the request's host or
    | headers. Required while a protocol is on; an application with another
    | layout binds its own resolver.
    |
    */

    'endpoints' => [
        'base_url' => env('SSO_BASE_URL'),

        'paths' => [
            'assertion_consumer_service' => '/auth/sso/connections/{connection}/assertions',
            'callback'                   => '/auth/sso/connections/{connection}/callback',
            'metadata'                   => '/auth/sso/connections/{connection}/metadata',
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
    | `max_response_bytes` or slower than `timeout_seconds` fails, and a request
    | that carries no credential follows at most `max_redirects` redirects,
    | each checked again (one that carries a credential follows none).
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
