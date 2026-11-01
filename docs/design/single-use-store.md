# Single-Use Store

## Purpose

This note records how a key is recorded once in its namespace until its expiry, atomically and shared by every server:
what the store guarantees, what the default stores and how it answers, how it behaves inside a caller's transaction, and
what another bound store must guarantee (SSO-11.5, SSO-11.4, SSO-11.3). The store backs SAML assertion ids (keyed by
connection and issuer, SSO-6.6), authorisation requests (SSO-5.1) and handoff codes (SSO-9.2).

## Invariants

- `Contracts\SingleUseStore::record($namespace, $key, $until)` answers `SingleUse\Enums\SingleUseOutcome`: `recorded`
  when the key was not held in the namespace and now is, until `$until`; `seen` when it was already held. Only
  `recorded` lets a flow proceed. A store that cannot answer with certainty (an error, a timeout, an answer it doubts)
  throws, and the flow is refused as a server error (SSO-11.4), never passed.
- Arguments are checked before any statement, each an `InvalidArgumentException` whose message never names the key: the
  namespace is 1 to 64 characters of `a-z`, `0-9`, `_`, `.`, `:` and `-` (with nothing after them, not even a newline);
  the key is any non-empty string; the expiry is after the clock's now.
- The caller builds the key, scoped as it must be: an assertion id is joined with its connection and issuer by the SAML
  completion, so one tenant's identity provider cannot record, or poison, another's ids. The caller also chooses
  the expiry: for an assertion id, the latest moment any acceptance rule would still accept it (each `NotOnOrAfter`
  and the `IssueInstant` maximum age, plus the skew).
- The default, `SingleUse\DatabaseSingleUseStore`, stores only the lower-case hex SHA-256 digest of the key
  (`key_digest`), never the key, since a key may be a secret (a handoff code). The row is `(namespace, key_digest,
  expires_at)` in `sso.single_use.table` (default `sso_single_use_keys`) on the storage connection, under a unique index
  on `(namespace, key_digest)`.
- The unique index answers, never a read: the store inserts the row, and an insert that goes in is `recorded`. An
  insert the index refuses (`UniqueConstraintViolationException`) is `seen`, unless the row it collides with has
  expired: then that row alone is deleted (`namespace`, `key_digest` and `expires_at <= now`, in one statement) and the
  insert tried once more, `recorded` if it goes in and `seen` if the index refuses it again. When no row was deleted,
  the answer is `seen`. Two concurrent records of one key therefore give exactly one `recorded`, on any number of
  servers.
- Every statement is a write, on the write connection (SSO-11.3), so a lagging replica can neither fail a valid record
  nor pass a replay.
- Each statement runs in a transaction of its own, which Laravel turns into a savepoint when the caller already has a
  transaction open. A refused insert is rolled back to its savepoint, so it never aborts the caller's transaction:
  PostgreSQL refuses every statement after a failed one until the transaction or a savepoint is rolled back. Inside a
  transaction, Laravel also throws a lost connection rather than reconnecting and running the insert again, so an
  insert that went in before the connection dropped is never answered `seen`.
- A statement the database rolls back as a deadlock or a serialisation failure wrote nothing, so it is tried again, at
  most three times in all, when the store opened the transaction itself: two inserts racing for a key whose expired
  row was just deleted can deadlock on MySQL. Inside the caller's transaction it is thrown at once
  (`DeadlockException`), since the database has rolled that transaction back too.
- Every other database error (`QueryException`, `PDOException`, a lost connection) propagates unchanged. The store
  catches nothing else, and never answers `recorded` or `seen` on an error.
- Times are whole seconds in UTC, whatever the application timezone, written and read through
  `Models\Casts\UtcDateTime`. The column holds no offset, so in a timezone with daylight saving the hour a fall-back
  repeats would name two instants with one value, and a held key could read as expired. The expiry is rounded up
  to the whole second, so a key is never released before its expiry; a key is released from the second its expiry names
  (`expires_at <= now`). Every comparison reads the one bindable clock (`Contracts\Clock`).
- The store holds nothing but its clock between calls, and is bound scoped (SSO-11.2).

## Success Path

- A first record of a key in a namespace inserts its row and answers `recorded`.
- A record of the same key in another namespace is a separate key, and is `recorded` too.
- Once the expiry has passed, the next record deletes the expired row, inserts the new one and answers `recorded`.
- `model:prune` on `Models\SingleUseKey` deletes the rows whose expiry has passed, by the package's clock; the store
  would release them anyway, so pruning only keeps the table small.

## Failure / Edge Cases

- A record of a key held and unexpired answers `seen`, and leaves its row untouched: a record never deletes a row still
  held, nor another key's row, expired or not.
- A key recorded by another server between the deletion of its expired row and the second insert is `seen`, and the
  other server's row is kept.
- A missing table, a dropped connection, a timeout or any other database error is thrown, and the flow is refused as a
  server error.
- Transactions:
  - A record made inside a caller's transaction is undone if that transaction rolls back: the key can be recorded again
    afterwards, and a deletion of an expired row is undone with it. A record inside a transaction that commits is held.
  - A caller that must keep a consumption whatever happens to the rest of its work (the completion consumes its
    authorisation request) records outside the transaction it may roll back, so a later failure cannot make the
    request usable again.
  - A caller that records inside its transaction does so on the storage connection; a record through another
    connection is not part of that transaction.
- Another bound store must:
  - be atomic: two concurrent records of one key answer exactly one `recorded`;
  - be shared by every server and process (not an in-process array or a per-server cache);
  - keep each key until its expiry, never evicting one earlier (a cache that may evict under memory pressure does not
    qualify);
  - read from the write connection or the primary;
  - throw on any error, timeout or doubt, never answering `recorded` or `seen` it is not sure of;
  - keep only what it needs of a key that may be a secret, never logging it or putting it in an exception message.

## Implementation Anchors

- `src/Contracts/SingleUseStore.php`; `src/SingleUse/Enums/SingleUseOutcome.php`.
- `src/SingleUse/DatabaseSingleUseStore.php`: `record()`, `assertValid()`, `store()`, `deleteExpired()`, `format()`.
- `src/Models/SingleUseKey.php`: `prunable()`; `src/Models/Casts/UtcDateTime.php`.
- `database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php`.
- `src/SsoServiceProvider.php`: the `scopedIf` binding of `SingleUseStore`.

## Authoritative Tests

- `tests/Unit/SingleUse/DatabaseSingleUseStoreArgumentsTest.php`
- `tests/Feature/SingleUse/DatabaseSingleUseStoreTest.php`
- `tests/Feature/Models/SingleUseKeyTest.php`
- `tests/Feature/Models/Casts/UtcDateTimeTest.php`
- `tests/Integration/SingleUse/SingleUseKeysMigrationTest.php`
- `tests/Integration/SingleUse/SingleUseStoreTransactionTest.php`
- `tests/Integration/SingleUse/ConcurrentSingleUseStoreTest.php` (MySQL and PostgreSQL; skipped on SQLite)
- `tests/Unit/SingleUse/SingleUseOutcomeTest.php`
- `tests/Performance/SingleUseStoreQueryBudgetTest.php`: the statements of each path, and that each is data
  manipulation only.

## Change Triggers

- A new namespace, or a caller that records a key: its key scoping, its expiry, and whether it records inside or
  outside its transaction.
- Any change to the table's columns or indexes, to how the expiry is stored or compared, or to which exceptions are
  caught or retried.
- A store that answers from a read, a cache or another connection.
