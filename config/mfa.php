<?php

declare(strict_types = 1);

use SineMacula\Laravel\Authentication\Models\Device;

return [

    /*
    |---------------------------------------------------------------------------
    | Device tracking
    |---------------------------------------------------------------------------
    |
    | Configures the package's default Eloquent device adapter. JWT refresh
    | lookup and rotation require `device.model` to be an Eloquent model
    | implementing the package `EloquentDevice` contract. The shipped migration
    | and model use the conventional schema below; custom models may remap
    | columns via their public column-name accessors. Bearer-path last-seen
    | persistence is driven by the bound device instance itself, so it only runs
    | when that resolved device is a persisted EloquentDevice.
    |
    */

    'device' => [
        'model'                      => env('AUTHENTICATION_DEVICE_MODEL', Device::class),
        'table'                      => env('AUTHENTICATION_DEVICE_TABLE', 'devices'),
        'refresh_key_column'         => env('AUTHENTICATION_DEVICE_REFRESH_KEY_COLUMN', 'refresh_key'),
        'last_seen_throttle_seconds' => (int) env('AUTHENTICATION_DEVICE_LAST_SEEN_THROTTLE_SECONDS', 60),
    ],

    /*
    |---------------------------------------------------------------------------
    | Credentials
    |---------------------------------------------------------------------------
    |
    | Field name the BasicGuard passes to the identity provider when building
    | credentials from HTTP Basic headers. Override when the identity model keys
    | off `username`, `phone`, etc.
    |
    */

    'credentials' => [
        'identifier_field' => env('AUTHENTICATION_IDENTIFIER_FIELD', 'email'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Credential validation timing
    |---------------------------------------------------------------------------
    |
    | Microsecond budget passed to Illuminate\Support\Timebox on the
    | credential-validation path. Must exceed the worst-case hasher cost (bcrypt
    | cost 12 ≈ 150–250ms) or timing-safety breaks down.
    |
    */

    'timebox' => [
        'credentials_microseconds' => (int) env('AUTHENTICATION_TIMEBOX_CREDENTIALS_US', 400000),
    ],

    /*
    |---------------------------------------------------------------------------
    | Resolution cache
    |---------------------------------------------------------------------------
    |
    | Optional shared cache for live bearer identity rehydration on the JWT
    | access-token path. Disabled by default. Basic credential lookups, bearer
    | device resolution, and the entire refresh flow remain live-only.
    |
    | Safe enablement requires explicit invalidation wiring in the consumer app
    | when identity auth identifiers or active-state flags change.
    |
    */

    'resolution_cache' => [
        'store' => env('AUTHENTICATION_RESOLUTION_CACHE_STORE'),
        'jwt'   => [
            'identity_ttl_seconds'  => (int) env('AUTHENTICATION_RESOLUTION_CACHE_JWT_IDENTITY_TTL_SECONDS', 0),
            'principal_ttl_seconds' => (int) env('AUTHENTICATION_RESOLUTION_CACHE_JWT_PRINCIPAL_TTL_SECONDS', 0),
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | JWT
    |---------------------------------------------------------------------------
    |
    | Sessionless JWT defaults consumed by JwtTokenService and JwtGuard. Access
    | tokens are self-verifying and are not backed by a server-side access-token
    | store, but JwtGuard still rehydrates identity, principal, and optional
    | device state on bearer authentication. A resolved, persisted device may
    | still trigger normal device-authenticated side effects such as debounced
    | last-seen writes. Configure either `secret` (single-secret mode) or `keys`
    | + `active_kid` (kid-based rotation). Invalid signing material fails
    | closed when a JWT guard or token service is resolved. `issuer`/`audience`
    | are optional; when set they are strictly verified on every parse.
    |
    */

    'jwt' => [
        'secret' => env('AUTHENTICATION_JWT_SECRET'),

        // Optional `kid => secret` map for graceful key rotation. When
        // populated, takes precedence over `secret` above.
        'keys' => [],

        // Kid in the `keys` map that signs newly issued tokens. Required when
        // `keys` is non-empty.
        'active_kid' => env('AUTHENTICATION_JWT_ACTIVE_KID', ''),

        'algorithm'           => env('AUTHENTICATION_JWT_ALGORITHM', 'HS256'),
        'access_ttl_minutes'  => (int) env('AUTHENTICATION_JWT_ACCESS_TTL_MINUTES', 15),
        'refresh_ttl_minutes' => (int) env('AUTHENTICATION_JWT_REFRESH_TTL_MINUTES', 60 * 24 * 30),
        'leeway_seconds'      => (int) env('AUTHENTICATION_JWT_LEEWAY_SECONDS', 30),
        'issuer'              => env('AUTHENTICATION_JWT_ISSUER'),
        'audience'            => env('AUTHENTICATION_JWT_AUDIENCE'),
    ],
];
