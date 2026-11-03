# Operations

The package has four commands to run on a schedule: one deletes what it no longer needs, one checks verified domains
again, one refreshes what connections fetch from their identity providers, and one reports the keys and certificates
nearing expiry. This guide covers registering them, how often they run, what they need, what their exit codes mean and
what to do when one stops partway.

## Registering the schedule

Register all four in one call, on every server that runs the scheduler:

```php
// bootstrap/app.php
use Illuminate\Console\Scheduling\Schedule;
use SineMacula\Laravel\Sso\Operations\OperationsSchedule;

->withSchedule(function (Schedule $schedule): void {
    app(OperationsSchedule::class)->register($schedule);
})
```

Nothing is registered while no protocol is on, since the tables the commands read may not exist yet.

### Cadences

| Task               | Command                | Default       | Setting                                   | Env                                       |
|--------------------|------------------------|---------------|-------------------------------------------|-------------------------------------------|
| `prune`            | `sso:prune`            | `0 * * * *`   | `sso.operations.cadence.prune`            | `SSO_OPERATIONS_PRUNE_CADENCE`            |
| `domain_recheck`   | `sso:domains:recheck`  | `0 * * * *`   | `sso.operations.cadence.domain_recheck`   | `SSO_OPERATIONS_DOMAIN_RECHECK_CADENCE`   |
| `metadata_refresh` | `sso:metadata:refresh` | `*/5 * * * *` | `sso.operations.cadence.metadata_refresh` | `SSO_OPERATIONS_METADATA_REFRESH_CADENCE` |
| `expiry_report`    | `sso:keys:expiring`    | `0 0 * * *`   | `sso.operations.cadence.expiry_report`    | `SSO_OPERATIONS_EXPIRY_REPORT_CADENCE`    |

Each is a cron expression. Set one to `null` or empty to leave that task to your own schedule; a malformed one fails
`php artisan sso:check` under `[operations]`.

> [!IMPORTANT]
> Linking by email stops 24 hours after a domain's last successful check, whatever the schedule, and sooner if
> `sso.domains.linking_max_age_seconds` says so. Keep `domain_recheck` well inside that age: hourly leaves room for a
> few failed runs.

### Several servers, and the cache

Every command is safe to run on several servers at once, by what it does in the database:

| Command                | What keeps servers apart                                                                |
|------------------------|-----------------------------------------------------------------------------------------|
| `sso:prune`            | Each batch deletes by key with the eligibility repeated; a row goes once                |
| `sso:domains:recheck`  | One server leases each domain for the check, and the others skip it                     |
| `sso:metadata:refresh` | One refresh claims each connection; duplicate jobs find it no longer due and do nothing |
| `sso:keys:expiring`    | One reporter claims each key while it sends the warning                                 |

So by default each runs on every server, none of the four reads or writes the cache, and no stale mutex can stop
maintenance. If you would rather save the work, opt in to Laravel's mutexes, `withoutOverlapping()` and `onOneServer()`,
for all four:

```dotenv
SSO_OPERATIONS_CACHE_MUTEXES=true
SSO_OPERATIONS_MUTEX_MINUTES=60
```

They save work and guarantee nothing, and they need a cache every server shares, whose driver supports locks. They use
the store your schedule uses, which `Schedule::useCache()` chooses.

#### Recovering from a stuck mutex

A process that dies holding a mutex stops that command until the mutex expires, `mutex_minutes` later (an hour by
default, where Laravel's own default is a day). If a command has not run and you know why, clear it rather than wait:

```bash
php artisan schedule:clear-cache
```

Turning `SSO_OPERATIONS_CACHE_MUTEXES` off also takes effect at once, since the commands do not depend on the mutexes.

#### `schedule:run` and your cache

`schedule:run` itself is Laravel's, and Laravel 13 reads its pause signal from your default cache before it runs any
task. With that cache down, or answering anything truthy for the signal, nothing on your schedule runs, these four
included, though no sign-in depends on them. If maintenance must go on through a cache outage, do one of these:

- Call `Schedule::withoutInterruptionPolling()` in your application. `schedule:run` then never asks the cache, but
  `schedule:pause` and `schedule:interrupt` stop working for every task you schedule.
- Run the four commands from your system's cron rather than through `schedule:run`, setting their cadences to `null`.
  None of them needs the cache.

### Queues

`sso:metadata:refresh` sends each refresh to the queue, so run a worker (or pass `--sync` to refresh in the command). See
[SAML metadata](saml-metadata.md) for the queue settings. The other three do their work in the command. Queued listeners
of the events each one dispatches need a worker too.

## Exit codes

| Command                | 0                                                  | 1                                                               |
|------------------------|----------------------------------------------------|-----------------------------------------------------------------|
| `sso:prune`            | Complete, or incomplete with the next run to go on | A kind stopped on an exception; what committed before it stands |
| `sso:domains:recheck`  | Every lookup answered                              | A lookup failed, or the run stopped on an exception             |
| `sso:metadata:refresh` | Whatever the refreshes' outcomes                   | The run stopped on an exception                                 |
| `sso:keys:expiring`    | However many keys are expiring or have expired     | A warning's dispatch threw, or the run stopped on an exception  |

An exception is named by its class alone, since its message could carry a value read from the database. Hook
`onFailure()`, or watch the scheduler's output, to hear of a non-zero exit.

## Pruning

`php artisan sso:prune` deletes:

| What                   | When it goes                                           |
|------------------------|--------------------------------------------------------|
| Authorisation requests | A day after they expire, whatever happened to them     |
| Handoff codes          | A day after they expire, whatever happened to them     |
| Single-use keys        | As they expire                                         |
| Link reservations      | As they expire, raising the connection's links version |
| Pending domain claims  | As they expire                                         |
| Rate limit counters    | As their window ends, on the counters' connection      |

Connections, keys, verified and lapsed domains, active and suspended links and identity guards are never pruned.

| Key                         | Default  | Env                             | What it sets                                                                     |
|-----------------------------|----------|---------------------------------|----------------------------------------------------------------------------------|
| `pruning.retention_seconds` | `86400`  | `SSO_PRUNING_RETENTION_SECONDS` | How long past its expiry a request or a code is kept: `0` to `7776000` (90 days) |
| `pruning.batch_size`        | `1000`   | `SSO_PRUNING_BATCH_SIZE`        | How many rows one statement names: `1` to `10000`                                |
| `pruning.max_rows_per_kind` | `100000` | `SSO_PRUNING_MAX_ROWS_PER_KIND` | How many rows one run looks at of each kind: `1` to `100000000`                  |

The retention is there so you can look at a recent flow. It is not what makes pruning safe, and shortening it, to `0`
even, is safe: a flow checks its expiry and locks what it writes, whether the row is still there or not. On SQLite before
3.32, keep the batch under 999.

### Partial progress

Each batch commits by itself, so a run never holds a long transaction, and whatever it committed stands however it ends.

- **Incomplete**: a kind reached `max_rows_per_kind` with more eligible. The other kinds still had their turn. The run
  says so, logs a warning and exits 0, and the next run goes on. To clear a backlog at once:

  ```bash
  php artisan sso:prune --drain
  ```

  A drain takes no cap, and ends on what was eligible when it started.
- **Failed**: a kind stopped on an exception. The other kinds still had their turn, the output and the log say what
  committed and which kind failed, and it exits 1. Run it again once the cause has gone: it finds what is left.

A run logs one line, `sso.prune.finished`, with the outcome, the duration, the counts and any failed kind with its
exception's class. It dispatches no event.

From your own code, `app(Pruner::class)->run()` answers a `PruneReport`, and throws `PruneFailedException`, holding the
report, when a kind failed. It refuses to run inside a transaction on either connection.

`model:prune` on `SingleUseKey` and `RateLimit` keeps working and deletes the same rows, but `sso:prune` covers
everything and is all you need.

### A store of your own

The package prunes its own tables. If you bind your own `SingleUseStore`, `HandoffIssuer` or `AttemptLimiter`, or a link
storage with its own reservations, cleaning it up is yours to do: the contracts expose no way to prune it. Keep the
published migrations in any case; with another store bound those tables stay empty, and pruning them does nothing.

## Keys and certificates nearing expiry

`php artisan sso:keys:expiring` lists every key and certificate whose validity ends within the largest threshold, or
has ended, on every run, whatever was notified before, so a problem nobody has solved stays visible:

```text
[expired] key 01jb... (connection 01jb..., idp_signing) ends 2026-10-31T12:00:00Z, threshold 0: already_notified
[expiring] key 01jb... (connection 01jb..., sp_signing) ends 2026-11-02T12:00:00Z, threshold 1: notified
Keys listed: 2, expired 1; warnings: notified 1, already_notified 1, not_due 0, claimed 0, failed 0
```

`--days=60` lists further ahead, or less far, for a look at what is coming. It does not change which warnings are sent.

| Key                         | Default             | Env                             | What it sets                                                                        |
|-----------------------------|---------------------|---------------------------------|-------------------------------------------------------------------------------------|
| `keys.expiry_thresholds`    | `[30, 14, 7, 1, 0]` |                                 | The days before its end of validity a key is warned of: `0` to `365`, including `0` |
| `keys.expiry_claim_seconds` | `300`               | `SSO_KEYS_EXPIRY_CLAIM_SECONDS` | How long one reporter holds a key while it sends a warning: `1` to `3600`           |

The expiry is reported, never enforced: an expired certificate is still trusted, since trust comes from the certificate
you configured, not its dates.

### What a warning promises

Listen for `KeyNearingExpiry`, which carries `thresholdDays`, and tell an administrator to rotate:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;

Event::listen(KeyNearingExpiry::class, function (KeyNearingExpiry $event): void {
    SecurityTeam::notify(new CertificateExpiring($event->context()->connectionId, $event->fingerprint, $event->notAfter, $event->thresholdDays));
});
```

- **The most urgent threshold reached**: a key warned of nothing with six days left gets one warning, for `7`, and none
  for `30` or `14`. Thresholds passed while nothing ran are skipped, and `0` is sent when its validity has ended.
- **It only escalates**: a key is never warned of a less urgent threshold than the last. If you change the thresholds, a
  key stays quiet until it reaches one more urgent than the last it was warned of.
- **At least once**: a warning is recorded as sent only after it is dispatched. If the process dies in between, or a
  listener throws, a later run sends it again, so you may see one twice but never lose one. A listener that must act only
  once keeps its own record of `keyId` and `thresholdDays`.
- **Several servers**: one reporter holds a key for `expiry_claim_seconds` while it sends, and the others report it as
  `claimed`. If that reporter dies, a run after the claim runs out sends the warning.
- **A failed dispatch**: a listener that throws ends that key with `failed`, logged by the exception's class, the next
  key goes on, and the command exits 1.

Like any event, a warning that reached a queued listener's queue has been dispatched: delivery past that point is the
queue's.

From your own code, `app(ExpiryReport::class)->report($days, $each)` hands each entry to the closure as it reads it,
since it keeps none in memory, and answers the counts. It refuses to run inside a transaction.
