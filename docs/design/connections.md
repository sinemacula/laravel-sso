# Connections and Protocol Drivers

## Purpose

This note records what a connection is in storage, how a protocol is plugged in behind one contract, what makes a
connection usable, and how presets fill in settings (SSO-2.1, SSO-2.2). Every later part of the package (management,
keys, domains, enforcement, links, the flows) reads a connection through what is described here.

## Invariants

- A connection is one row of `sso_connections` (`connections.table`), on the storage connection, read and written
  through `Models\Connection`. It holds:

  | Column                  | What it holds                                                                          |
  |-------------------------|----------------------------------------------------------------------------------------|
  | `id`                    | A lower-case ULID, the `{connection}` of the connection's endpoints                    |
  | `tenant_id`             | The tenant, an opaque string id the application gives                                  |
  | `protocol`              | The name of a registered driver (`saml2`, `oidc` or the application's own)             |
  | `display_name`          | The name administrators know the connection by                                         |
  | `settings`              | JSON: the protocol's settings by name, never a secret                                  |
  | `secrets`               | JSON: each secret setting's name and its `SecretEncrypter` ciphertext, or `null`       |
  | `attribute_mapping`     | JSON: each target attribute of the result by the SAML attribute or OIDC claim it reads |
  | `enabled`               | Whether the connection is enabled (default `false`)                                    |
  | `has_completed_sign_in` | Whether a `sign_in` through it has been redeemed (default `false`; SSO-4.3)            |
  | `links_version`         | Raised by one for each link created through it (default `0`; see `links.md`)           |
  | `created_at`            | When it was created, whole seconds in UTC, from the package's clock                    |
  | `updated_at`            | When it last changed, whole seconds in UTC, from the package's clock                   |

- The tenant and the protocol are fixed at creation. The management helpers refuse a change to either as a value
  (`ViolationCode::IMMUTABLE`); the model throws a `LogicException` if one reaches it anyway, before anything is
  written.
- A new connection is disabled, has completed no sign-in, and has no settings or mapping until it is given them.
- Tenant ids are opaque and compared exactly, whatever the column's collation. `Connections\ConnectionFinder` narrows
  by `tenant_id` in the statement, then keeps a row only when its recorded tenant id is byte for byte the one given, so
  under a collation such as MySQL's default `_ci` (which counts `acme`, `Acme` and `acme` as equal) another tenant's
  connection is still answered exactly as an unknown one.
- Secrets never sit among the settings: they are taken out of what an administrator gives by the protocol's
  `secretNames()`, each encrypted on its own through `Contracts\SecretEncrypter` and kept under its name in `secrets`
  (so a read masks them by name without decrypting one), hidden from serialisation, and never returned by a helper
  (SSO-2.5). `Contracts\SsoConnection` exposes no secret.
- `has_completed_sign_in` has exactly one writer: the redemption of a `sign_in` handoff code (BL-35), by the package's
  own redemption or an adapter's acknowledgement in its redemption transaction. `link`, `reauthenticate`, an issued but
  unredeemed code and an unlinked handoff never set it. Nothing in P1 writes it.
- `links_version` has exactly one writer: `Links\LinkStore::create()`, which raises it by one, under the connection's
  lock, for each link it inserts. It means nothing on its own; it makes a link's insert also write the connection's row,
  so a PostgreSQL `REPEATABLE READ` transaction that locks the row after the creation commits fails to serialise rather
  than go on without the link (see `flows.md`'s lock order).
- Each model of a record (connections, keys and certificates) is keyed and stamped by
  `SsoModel::identifiedAndStamped()`: a lower-case ULID unless one is set, and `created_at` and `updated_at` from
  `Contracts\Clock` (SSO-11.13), stored in UTC through `Casts\UtcDateTime`. Laravel's own timestamps are off, so a
  write through the query builder bypasses the stamps; the package writes these models through the model.
- `Casts\UtcDateTime` never hands back the object it was given: every read is the `CarbonImmutable` in UTC the stored
  value names.
- A protocol is a driver behind `Contracts\ProtocolDriver`: it reads a connection's settings (`settings()`, typed as
  `Contracts\ProtocolSettings`), says whether a connection is complete (`isComplete()`), starts an authorisation
  request (`start()`), completes it (`complete()`) and describes the service provider side (`describe()`). Expected
  refusals are values (`Protocols\Start`, `Protocols\Completion`, `Protocols\ServiceProviderDescription`, each carrying
  a `FailureReason`); a database error, a misconfiguration or a library failure propagates.
- A driver reads a connection only through `Contracts\SsoConnection` (an architecture rule forbids `Protocols` to name
  `Models`), and holds no connection, tenant, flow or result state between calls (SSO-11.2).
- `Protocols\ProtocolManager` is the registry, in the style of `laravel-authentication`'s `SignInMethodManager`:
  - a container singleton (`singletonIf`) that builds each driver once for the application serving, and again for each
    Octane sandbox, keeping drivers registered with `extend()`; a manager given its own container keeps it;
  - the package's drivers, `saml2` and `oidc`, are reserved: `extend()` refuses them;
  - a driver is registered under a lower-case name of up to 64 characters (a letter, then letters, digits or
    underscores) and resolves only by exactly that name; any other spelling is unknown (`InvalidArgumentException`);
  - there is no default driver;
  - a registered closure that does not build a `ProtocolDriver` fails with a `LogicException` naming the protocol.
- A protocol is available while a driver is registered under it and its feature is on: `saml2` with
  `sso.features.saml2`, `oidc` with `sso.features.oidc`, an application's driver with either. A malformed switch fails
  closed with `Config\Features::enabled()`'s `InvalidArgumentException`.
- A connection is usable (SSO-2.1) only while it is enabled, its protocol is available, and its driver finds it complete
  (`ProtocolManager::isUsable()`). The caller deciding whether a flow may run reads the connection from the write
  connection first (SSO-11.3).
- Until P4 and P5 land, the `saml2` and `oidc` drivers are placeholders (`Protocols\PlaceholderDriver`): they read their
  protocol's settings through `Protocols\Saml2\Saml2Settings` and `Protocols\Oidc\OidcSettings`, find no connection
  complete, refuse every start and completion with `connection_unavailable`, and describe nothing. Nothing can sign in
  through them, however they are configured.
- The settings' names, and how a change to each is classified, are fixed in `Protocols\Saml2\Enums\Saml2Setting` and
  `Protocols\Oidc\Enums\OidcSetting`: the freshness operation a change needs (`sso.connection.trust` for trust,
  endpoints, subject, signature and algorithm settings and the client's credentials; `sso.connection.idp_initiated`
  for IdP-initiated sign-in; none for request options), whether a change may alter what existing subjects mean
  (SSO-2.13), and which is a secret. A driver an application registers classifies its own through
  `ProtocolSettings::freshnessFor()`, `subjectNames()` and `secretNames()`.
- A refused setting is a `Connections\SettingViolation`: the dotted path of the setting and a
  `Connections\Enums\ViolationCode`, never its value.
- Presets are data (`Protocols\Preset`): a protocol, the settings and attribute mapping it fills in, and, for an issuer
  many organisations share, the claim naming the organisation (SSO-8.8). What an administrator gives replaces what a
  preset fills in, setting by setting (`fill()`, `fillMapping()`), so every check applies as it does to settings entered
  by hand. The package ships `google`, `microsoft_entra`, `okta`, `auth0` and `microsoft_entra_saml`
  (`Protocols\Presets`); an application registers its own with `ProtocolManager::registerPreset()`, never under a
  shipped name and only for a registered protocol. A preset never holds a secret.
- The flow value types (`Protocols\StartRequest`, `Start`, `Navigation`, `CompletionRequest`, `Completion`,
  `ServiceProviderDescription`) are the contract's shape now; the authorisation request (BL-32) and completion pipeline
  (BL-34) add to them, through new named constructors and fields, before the real drivers land. `StartRequest` holds
  the protocol state as `Secrets\Secret` values, and `CompletionRequest` (which carries an assertion or a code) shows
  nothing in a dump and refuses to be serialised.

## Success Path

1. The application turns `sso.features.oidc` (or `saml2`) on, publishes and runs the migrations.
2. A connection is created disabled through the management helpers, optionally from a preset.
3. It is given its settings, keys and certificates, and enabled.
4. `ProtocolManager::isUsable()` answers `true` once the driver finds it complete; a flow resolves the driver by the
   connection's protocol and starts.

An application adds a protocol by registering a driver once the registry resolves:

```php
$this->callAfterResolving(ProtocolManager::class, fn (ProtocolManager $protocols) => $protocols->extend('cas', fn () => new CasDriver));
```

## Failure / Edge Cases

- A connection whose protocol is no longer registered, or whose feature is off, is never usable; its row is kept.
- A disabled connection, or one its driver finds incomplete, is never usable, and a flow refuses it with
  `connection_unavailable`, the same answer for each (SSO-3.5).
- `extend('saml2', ...)`, a malformed name, or a closure that builds something else, fails as a misconfiguration.
- A preset under a shipped name, or for a protocol not registered, is refused with an `InvalidArgumentException`.
- A malformed `connections.table` or storage connection fails closed when a model is built; `[storage]` reports both.

## Implementation Anchors

- `src/Models/Connection.php`, `src/Models/SsoModel.php` (`identifiedAndStamped()`), `src/Models/Casts/UtcDateTime.php`.
- `database/migrations/2026_11_01_000000_create_sso_connections_table.php`; `src/Database/StorageConnection.php`
  (`TABLES`).
- `src/Contracts/SsoConnection.php`, `src/Contracts/ProtocolDriver.php`, `src/Contracts/ProtocolSettings.php`.
- `src/Protocols/ProtocolManager.php`, `src/Protocols/PlaceholderDriver.php`, `src/Protocols/Saml2/Saml2Driver.php`,
  `src/Protocols/Oidc/OidcDriver.php`.
- `src/Protocols/Saml2/Enums/Saml2Setting.php`, `src/Protocols/Oidc/Enums/OidcSetting.php`.
- `src/Protocols/Preset.php`, `src/Protocols/Presets.php`.
- `src/Protocols/StartRequest.php`, `Start.php`, `Navigation.php`, `CompletionRequest.php`, `Completion.php`,
  `ServiceProviderDescription.php`, `src/Flows/Enums/Purpose.php`.
- `src/Connections/SettingViolation.php`, `src/Connections/Enums/ViolationCode.php`.
- `src/SsoServiceProvider.php`: the `ProtocolManager` binding and the migration.

## Authoritative Tests

- `tests/Feature/Protocols/ProtocolManagerTest.php`
- `tests/Unit/Protocols/PlaceholderDriverTest.php`
- `tests/Feature/Models/ConnectionTest.php`, `tests/Feature/Models/Casts/UtcDateTimeTest.php`
- `tests/Integration/Connections/ConnectionsMigrationTest.php`, `tests/Integration/Connections/ConnectionUsabilityTest.php`
- `tests/Unit/Protocols/PresetTest.php`, `tests/Unit/Protocols/PresetsTest.php`
- `tests/Unit/Protocols/Saml2/Enums/Saml2SettingTest.php`, `tests/Unit/Protocols/Oidc/Enums/OidcSettingTest.php`
- `tests/Unit/Protocols/NavigationTest.php`, `StartTest.php`, `StartRequestTest.php`, `CompletionTest.php`,
  `CompletionRequestTest.php`, `ServiceProviderDescriptionTest.php`
- `tests/Unit/Connections/SettingViolationTest.php`, `tests/Unit/Connections/Enums/ViolationCodeTest.php`
- `tests/Feature/Connections/ConnectionFinderTest.php` (tenant ids matched exactly, the row locked only for update)
- `tests/Unit/Architecture/NamespaceDependenciesTest.php` (protocol drivers read a connection through its contract)

## Change Triggers

- A column of `sso_connections`, or what one may hold.
- A method of `ProtocolDriver`, `ProtocolSettings` or `SsoConnection`, or a flow value type's shape.
- A setting name, or how a change to one is classified.
- A shipped preset, or how presets fill in settings.
- What makes a protocol available or a connection usable.
- A second writer of `has_completed_sign_in`.
