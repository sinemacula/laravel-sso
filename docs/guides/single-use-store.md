# Single-Use Keys

Some things the package accepts must be accepted once only: a SAML assertion (a replayed assertion is refused), an
authorisation request (consumed by the completion it started) and a handoff code (redeemed once). Each is recorded
through one contract, `SineMacula\Laravel\Sso\Contracts\SingleUseStore`, which records a key once in its namespace
until an expiry and answers whether it was new:

```php
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

$outcome = app(SingleUseStore::class)->record('handoff_code', $code, $expiresAt);

if ($outcome !== SingleUseOutcome::RECORDED) {
    // `seen`: already used, refuse it.
}
```

Only `recorded` lets a flow proceed. `seen` means the key is already held: a replay, refused. A store that cannot tell
throws, and the flow fails as a server error, never as a pass. The namespace is 1 to 64 characters of lower case
letters, digits, `_`, `.`, `:` and `-`; the key is any non-empty string; the expiry must be after now. Anything else is
an `InvalidArgumentException`, whose message never contains the key.

## The table

By default the keys are recorded in the database, on the storage connection (see
[Storage](configuration.md#storage)), in one table:

| Key                | Default               | Env                    |
|--------------------|-----------------------|------------------------|
| `single_use.table` | `sso_single_use_keys` | `SSO_SINGLE_USE_TABLE` |

The name must be a plain table name (letters, digits and underscores, not starting with a digit), optionally after a
schema and a dot; anything else fails closed when the table is used, and `php artisan sso:check` reports it under
`[storage]`, with any other table of the same name on the same connection.

Each row holds the namespace, the SHA-256 digest of the key (never the key itself, which may be a secret such as a
handoff code) and the expiry, to the whole second. A unique index on the namespace and the digest is what answers
`seen`, so a key is recorded once however many servers record it at the same moment.

## Publishing and migrating

The package never runs its migrations. Publish them and migrate, as the application's migration user:

```bash
php artisan vendor:publish --tag=sso-migrations
php artisan migrate
```

The migration creates the table under its configured name on the storage connection, where the store reads and writes
it. It refuses to run over an existing table of that name, before changing anything, with a
`TableAlreadyExistsException` naming `single_use.table`: set another name and migrate again. At run time the store
and `model:prune` need only `SELECT`, `INSERT` and `DELETE` on the table.

To rename or move the table, change the setting and migrate in one deploy, then restart every worker: the store reads
the setting when it records, and a table created under another name or on another connection is not found.

## Transactions

The store records on the storage connection. Recorded inside a transaction on that connection, a key is undone with
the transaction if it rolls back, and can be recorded again afterwards; a `seen` answer never aborts the transaction,
on PostgreSQL included, so the rest of the work can go on (or be rolled back) as the caller decides.

A consumption that must stand whatever happens next is recorded before, and outside, the transaction that may roll
back. A database error, a dropped connection or a timeout is always thrown, inside a transaction or not.

## Pruning

A key whose expiry has passed is released by the next record of it, but its row stays until it is pruned, which
`sso:prune` does along with everything else the package no longer needs: see [Operations](operations.md#pruning).
Laravel's `model:prune` works too, and takes the same rows, naming the package's model, since it lives outside your
`app/Models`:

```php
use Illuminate\Support\Facades\Schedule;
use SineMacula\Laravel\Sso\Models\SingleUseKey;

Schedule::command('model:prune', [
    '--model' => [SingleUseKey::class],
])->hourly();
```

Each chunk is one conditional `DELETE` of keys whose expiry has passed by the package's clock (see [Clock](clock.md)),
from the second it names. Pruning never releases a key that is still held, and changes nothing about what the store
answers: it only keeps the table small. To see how many keys would go:

```bash
php artisan model:prune --model="SineMacula\Laravel\Sso\Models\SingleUseKey" --pretend
```

## Binding another store

Bind your own implementation of `SingleUseStore` (in a service provider's `register()`) only if it gives every
guarantee the default does:

- **Atomic**: two concurrent records of one key answer exactly one `recorded`.
- **Shared**: every server, process and queue worker records in the same store; an in-process array or a per-server
  cache does not qualify.
- **Kept until the expiry**: a key is never evicted before its expiry; a cache that may evict under memory pressure,
  or on restart, does not qualify.
- **Read from the primary**: never from a replica, which may lag behind a record just made.
- **Certain or thrown**: on any error, timeout or answer it doubts, it throws; it never answers `recorded` (or `seen`)
  it is not sure of.
- **Careful with the key**: it may be a secret, so keep only a digest of it, and never log it or put it in an exception
  message.

```php
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;

$this->app->scoped(SingleUseStore::class, MySingleUseStore::class);
```

Bind it scoped (or as a plain binding), not as a singleton, if it holds anything from one request or job to the next.
A store that records outside the storage connection is never part of the package's transactions: a record it makes
inside one is kept when that transaction rolls back.
