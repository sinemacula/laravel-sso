# Storage

## Purpose

This note describes where the package's tables live, why they share one connection, how the runtime models and the
published migrations are kept choosing the same connection and the same table names, and the rule an adapter that must
commit with the package follows (SSO-11.7, SSO-11.10).

## Invariants

- One resolver decides, `Database\StorageConnection`: `name()` is `sso.storage.connection`, `null` or empty for the
  default connection; `forRateLimits()` is `sso.rate_limits.connection` when it names a connection, and `name()`
  otherwise; `connectionFor($key)` is the connection the table under `$key` lives on (the counters' for
  `rate_limits.table`, the storage connection for every other). A value that is neither a name nor `null` or empty
  fails closed with an `InvalidArgumentException` naming the key, rather than putting a table on another connection
  than the one meant.
- Every package table is listed in `StorageConnection::TABLES`, by the key under `sso.` of the setting that names it,
  with its default name, each with the `sso_` prefix (SSO-11.10). `table($key)` reads the setting, or the default when
  it is not set, and refuses anything but a plain table name, optionally schema-qualified. A key the list does not hold
  is a caller's mistake (`LogicException`).
- Every package model extends `Models\SsoModel` and names its table's key in `TABLE`; its constructor takes the table
  from `table()` and the connection from `connectionFor()`, so the model cannot read or write another table or
  connection than the one meant.
- Every published migration creates its table on `StorageConnection::connectionFor()` of its key, under `table()` of
  it, through `Schema::connection($this->getConnection())`, and guards it with `Database\MigrationCollisionGuard`, which
  refuses an existing table before changing anything and names the key that renames it. Laravel's migrator runs a
  migration, and its schema transaction, on the connection the migration names, so `php artisan migrate` and a direct
  `up()` or `down()` both put each table where its model reads and writes it.
- Migrations are published (`sso-migrations`) and run by the application's migration user, never loaded or run by the
  package; at run time the package needs only `SELECT`, `INSERT`, `UPDATE` and `DELETE` (SSO-11.7).
- The tables share the storage connection because a completion, a redemption, a connection's lifecycle change and a
  link's activation each write several of them in one transaction, which two connections cannot commit as one.
- An adapter that must commit with the package (a session revocation, a handoff consumed by the application's
  sign-in, a link activated with a session) writes through the same Laravel connection, inside the transaction the
  package opens. Reaching the same database through another connection, or another connection name for it, is not
  atomic. The contracts that need it say so, and their integration tests prove it.
- The attempt counters are the one table with an option of its own, so that counts can stay out of a transaction a
  refused flow rolls back; nothing writes them in a transaction with another package table.
- A completion, and a start that calls a protocol driver, run outside any transaction open on the storage connection:
  each refuses at entry with a `LogicException` (`StorageConnection::assertNoTransaction()`), so a caller's rollback
  never undoes a consumed request and a caller's transaction never keeps a connection's lock across a call to an
  identity provider (SSO-5.1, SSO-11.5).
- Security state (authorisation requests, single-use keys, handoff codes, links, domains, enforcement) is read from the
  write connection by the query that reads it (SSO-11.3); the model does not decide it.
- Locks are taken in one order, so two changes never wait on each other: an identity's guard (only what changes its
  verified domain links, `linking.md`), a tenant's enforcement row, then connection rows (in id order when several),
  then domain rows (one connection's claim by `connection_id` and `domain`, or every claim of one domain by the `domain`
  index in id order), then key rows. Under a lock, every read that decides a write is itself a locking read, since a
  plain read answers from the snapshot of a transaction the caller opened (MySQL's `REPEATABLE READ`). No locking read
  goes by a column whose only purpose is a unique guard (`verified_domain`): its MySQL gap locks would deadlock with the
  update that sets it, and the unique index guards it instead.
- A row of the application's opaque tenant id that must be unique per tenant (`sso_enforcement`) is keyed by the
  lower-case hex SHA-256 of the id (`Enforcement\TenantHash`), so a collation that counts `acme`, `Acme` and `acme`
  with a trailing space as equal cannot merge two tenants; a read by the hash still compares the id byte for byte. An
  identity's guard (`sso_identity_guards`) is keyed the same way, by a digest of its type and id, and names nobody.
- A model takes its connection and table when it is built, so the settings are deployment configuration, fixed for the
  life of a process.

## Success Path

- With both connection settings `null`, every model and table is on the default connection; run the migrations on it.
- With `sso.storage.connection` set, `php artisan migrate` creates every table on that connection, the counters
  included unless `sso.rate_limits.connection` names their own, and the models read and write them there.
- `php artisan sso:check` reports `[storage]` (each connection configured in `database.connections` or none, each table
  name well formed, no two tables of one connection with the same name) while the package is in use, reading
  configuration only.

## Failure / Edge Cases

- A malformed connection or table setting fails closed when a model is built or a migration runs; a name that
  `database.connections` does not configure fails on first use as Laravel's own error; the boot check and `sso:check`
  report both while the package is in use.
- Two tables configured to one name on one connection are reported by the check, before a migration fails on them.
- Changing a setting moves no table already created, and a rollback runs against the setting at the time it runs:
  moving or renaming the tables is a deploy, with a migration the application writes and a restart of every worker.
- A database error propagates as a server error (SSO-11.4), never as an invalid response, an unknown request, a failed
  redemption or a failure redirect.

## Implementation Anchors

- `src/Database/StorageConnection.php`: `TABLES`, `name()`, `forRateLimits()`, `connectionFor()`, `table()`,
  `holds()`.
- `src/Models/SsoModel.php`: the constructor and `identifiedAndStamped()`; `src/Database/MigrationCollisionGuard.php`.
- `src/Models/Connection.php`, `src/Models/ConnectionKey.php`, `src/Models/Domain.php`,
  `src/Models/TenantEnforcement.php`, `src/Models/IdentityGuard.php` and their migrations (`connections.table`,
  `keys.table`, `domains.table`, `enforcement.table`, `identity_guards.table`): records keyed by a ULID and stamped by
  the package's clock (see `connections.md`, `domains.md`, `enforcement.md`).
- `src/SsoServiceProvider.php`: `MIGRATIONS`, `registerPublishing()`; `src/Config/Checks/StorageCheck.php`;
  `config/sso.php`: `storage`, and each section's `table`.

## Authoritative Tests

- `tests/Feature/Database/StorageConnectionTest.php`
- `tests/Feature/Models/SsoModelTest.php`
- `tests/Integration/Database/StorageConnectionModelTest.php`
- `tests/Unit/Database/MigrationCollisionGuardTest.php`
- `tests/Feature/Config/Checks/StorageCheckTest.php`
- `tests/Feature/SsoServiceProviderTest.php` `testMigrationsArePublishedAndNeverLoaded`

## Change Triggers

- A new package table: its key and default in `TABLES`, its model extending `SsoModel`, its migration taking the
  resolver and the guard, and its file in the provider's `MIGRATIONS`.
- Any flow that writes two package tables in one transaction, or that would write one outside the storage connection.
- Any change to how connections are compared, or to what the counters' option allows.
