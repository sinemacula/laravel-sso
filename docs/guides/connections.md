# Connections

A connection is one tenant's trust in one identity provider over one protocol: its endpoints, certificates, keys,
secrets, attribute mapping and whether it is enabled. A tenant may have several. Connections are rows in the database,
managed through the package's helpers (see [Managing connections](managing-connections.md)), never entries in
`config/sso.php`.

## The table

Connections live in one table on the storage connection (see [Storage](configuration.md#storage)):

| Key                 | Default           | Env                     |
|---------------------|-------------------|-------------------------|
| `connections.table` | `sso_connections` | `SSO_CONNECTIONS_TABLE` |

Publish the migrations and migrate, as the application's migration user:

```bash
php artisan vendor:publish --tag=sso-migrations
php artisan migrate
```

Each connection has a lower-case ULID as its id, the `{connection}` of its endpoints, and keeps:

- its tenant, an opaque string id your application gives, and its protocol, both fixed when it is created;
- its display name, its settings by name, and its attribute mapping;
- its secrets, such as an OIDC client secret, encrypted at rest and never read back (see [Secrets](secrets.md));
- whether it is enabled, and whether a sign-in through it has ever been completed, which enforcement needs before it
  can be turned on.

A new connection is disabled. Read one through `SineMacula\Laravel\Sso\Contracts\SsoConnection`, which the package's
model implements and which never exposes a secret.

## Protocols

Each protocol is a driver behind `SineMacula\Laravel\Sso\Contracts\ProtocolDriver`, registered on
`SineMacula\Laravel\Sso\Protocols\ProtocolManager` under the name a connection's `protocol` holds. The package ships
`saml2` and `oidc`, each available while its switch in `sso.features` is on:

```php
'features' => [
    'saml2' => env('SSO_SAML2', false),
    'oidc'  => env('SSO_OIDC', false),
],
```

> [!NOTE]
> The SAML and OIDC drivers read and validate their settings, but their sign-in flows are still being built: until they
> are, no connection over either is usable, and every flow through one is refused.

## Registering your own protocol

Register a driver of your own under a lower-case name (a letter, then up to 63 letters, digits or underscores) once the
registry resolves, from a service provider's `register()`:

```php
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

$this->callAfterResolving(ProtocolManager::class, function (ProtocolManager $protocols): void {
    $protocols->extend('cas', fn () => new CasDriver);
});
```

The names `saml2` and `oidc` are the package's own and cannot be replaced. A driver resolves only by exactly the name it
was registered under, and is available while either protocol switch is on. The registry keeps one instance of each
driver per application (one per request under Octane), so a driver must hold no connection, tenant or flow state
between calls. It reads a connection through `SsoConnection`, and its settings through a class implementing
`Contracts\ProtocolSettings`, which also says which settings are secrets, which need fresh authentication to change
and which may change what existing subjects mean.

## When a connection is used

A connection is used only while it is usable: enabled, its protocol available, and its driver finding it complete
(settings, secrets, keys and certificates):

```php
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

app(ProtocolManager::class)->isUsable($connection);
```

A connection that is not usable is refused by every flow with `connection_unavailable`, the same answer whether it is
unknown, disabled or incomplete.

## Presets

Settings for well-known identity providers are presets: data that fills in a connection's settings and attribute
mapping, never a separate code path. What an administrator gives replaces what the preset fills in, setting by setting,
and every check applies as it does to settings entered by hand.

| Preset                 | Protocol | Fills in                                                                         |
|------------------------|----------|----------------------------------------------------------------------------------|
| `google`               | `oidc`   | Google's issuer and endpoints, scopes, algorithms, client authentication, claims |
| `microsoft_entra`      | `oidc`   | Scopes, algorithms, client authentication, claims; the issuer names your tenant  |
| `okta`                 | `oidc`   | Scopes, algorithms, client authentication, claims and groups                     |
| `auth0`                | `oidc`   | Scopes, algorithms, `client_secret_post`, claims                                 |
| `microsoft_entra_saml` | `saml2`  | Binding, persistent NameID, signed assertions, Entra's claim names               |

Google and Microsoft Entra ID serve many organisations from one issuer; their presets name the claim (`hd`, `tid`)
that says which organisation a sign-in belongs to. Register a preset of your own for a protocol that is registered:

```php
use SineMacula\Laravel\Sso\Protocols\Preset;

$protocols->registerPreset(new Preset('acme', 'oidc', [
    'scopes'              => ['openid', 'email', 'profile'],
    'id_token_algorithms' => ['ES256'],
], ['email' => 'email']));
```

A preset never holds a secret, and a shipped preset's name cannot be reused.
