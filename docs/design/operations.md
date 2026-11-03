# Operations

## Purpose

This note records the package's scheduled work (SSO-11.11, SSO-11.12): the clean-up of what it no longer needs, the
report of keys and certificates nearing expiry, the helper that puts the commands on the application's schedule, and
what makes each safe on several servers at once. How a domain is rechecked and how metadata is refreshed are in
`domain-rechecks.md` and `metadata-refresh.md`; this note records the audit of them.

## Invariants

### Scheduling

- `Operations\OperationsSchedule::register()` adds `sso:prune`, `sso:domains:recheck`, `sso:metadata:refresh` and
  `sso:keys:expiring` to the schedule given, each on `sso.operations.cadence.<task>`: a cron expression, by default
  hourly, hourly, every five minutes and daily, or `null` or empty to leave the task to the application. It registers
  nothing while no protocol is on, when the tables a command reads may not exist.
- Every command is correct under duplicate execution by what it does in the database, so by default each runs on every
  server and no task registered reads or writes a cache. A stale mutex can never suppress maintenance (SSO-11.6).
- `schedule:run` itself is the framework's. On Laravel 13 it reads its pause signal from the default cache before any
  task, so a cache that is down stops the whole schedule, and one that answers anything truthy reads as paused, until
  the application calls `Schedule::withoutInterruptionPolling()`, a choice for all of its tasks that also turns off
  `schedule:pause` and `schedule:interrupt`. `long-running-processes.md` records this. No flow depends on the schedule
  running: expiry and freshness are checked where they decide, and what a stopped schedule delays is the clean-up, the
  rechecks, the refreshes and the warnings.
- `sso.operations.cache_mutexes` opts in to `withoutOverlapping()` and `onOneServer()`, an optimisation that saves work
  and guarantees nothing. A mutex a dead process left expires after `sso.operations.mutex_minutes`, an hour by default
  and far short of Laravel's day. The package leaves the store to `Schedule::useCache()`, which applies to every task of
  the application.
- The commands exit non-zero on a failure, so `onFailure()` and the scheduler's output report it. An incomplete prune
  exits 0: the next run goes on.

### Pruning

- `Pruning\Pruner::run()` gives each `Pruning\Enums\PruneKind` its turn, in this order, each judged by the one instant
  it read from the clock:

  | Kind                     | Eligible when                                          | Connection    |
  |--------------------------|--------------------------------------------------------|---------------|
  | `authorization_requests` | `expires_at` <= now - retention, whatever its state    | storage       |
  | `handoff_codes`          | `expires_at` <= now - retention, whatever its state    | storage       |
  | `single_use_keys`        | `expires_at` <= now                                    | storage       |
  | `reservations`           | `state` = reserved and `reservation_expires_at` <= now | storage       |
  | `pending_claims`         | `state` = pending and `pending_expires_at` <= now      | storage       |
  | `rate_limits`            | `window_ends_at` <= now                                | the counters' |

- The retention is `sso.pruning.retention_seconds`, a day by default. It is for diagnosis and never a safety margin: a
  paused process's safety comes from its own expiry checks, its locked rechecks and its conditional writes. A completion
  delayed past its deadline (`Completion\VerifiedDeadlines`) refuses, whether its request is still there or not, and a
  locked recheck that finds the request gone refuses too.
- Refresh claims need no pruning. Identity guards are never pruned: they hold durable coordination and provenance.
- `Pruning\PruneTarget` selects at most `sso.pruning.batch_size` primary keys on the write connection, ordered by the
  time and the key and paged by keyset on that pair, never by offset; each table has an index in that order. It then
  deletes those keys with the whole eligibility repeated, so a row renewed, activated or verified since it was selected
  stands, and counts the rows affected, never the rows selected. The scan moves on by what it selected, so a batch
  another server has emptied does not end it.
- A batch is one statement, in a transaction of its own only so that a deadlock is tried again, at most three times in
  all. Reservations are the exception: `Links\ReservationWithdrawal::expired()` takes one short transaction for each of
  the batch's connections, ascending, that locks the connection, deletes what is still reserved and expired among the
  ids named, and raises the connection's `links_version` when it deleted any. Nothing else holds a lock across batches.
  `PruneTarget::units()` splits a batch into what commits together, and each is counted as it commits.
- A kind stops at `sso.pruning.max_rows_per_kind` rows looked at, so a backlog in one kind leaves every other its turn.
  When it stops there and more is eligible, which it asks rather than guesses, the run's status is `incomplete`. The
  next run goes on from what is left. `run(true)`, and `sso:prune --drain`, takes no cap; it still ends, on the rows
  eligible at its one instant.
- An exception stops the kind it came from, the kinds after it still take their turn, and the transactions committed
  before it stand and are reported, a connection's reservations among them when a later connection's fail. The run then
  throws `Pruning\PruneFailedException`, holding the report and chaining the first exception, so a database error still
  propagates (SSO-11.4). A run begun again finds what is left.
- A run refuses to start inside a transaction on the storage connection or the counters' (a `LogicException`), since it
  would turn every short batch into one long one.
- A run dispatches no event, being housekeeping and not an administrative change. It logs one line, `sso.prune.finished`,
  through the sanitising logger: `info` when complete, `warning` when incomplete, `error` when failed, with the outcome,
  the instant, the duration, the rows each kind deleted, the kinds incomplete, and each failed kind with its exception's
  class alone. It never logs a message, a binding or an identifier. A logger that throws on that line, a destination
  that cannot be written say, loses nothing: the run throws `PruneFailedException` all the same, holding the report and
  any kind's failure, with the logger's exception in `logFailure` (chained when no kind failed), and `sso:prune` prints
  the counts, each failed kind, and the logger's exception by class, and exits 1.
- `model:prune` still works on `Models\SingleUseKey` and `Models\RateLimit`, deleting what a run would (`expires_at` and
  `window_ends_at` at or before the clock's now). It is one chunked statement after another with no work cap and no
  report; `sso:prune` is the entry point that covers everything.

### Application-supplied stores

- The contracts `SingleUseStore`, `HandoffIssuer` and `AttemptLimiter` expose no pruning operation, so an application
  that binds its own store cleans it up itself. `sso:prune` prunes the package's own tables whatever is bound: with
  another store bound those tables are empty, and pruning them does nothing. The migrations stay published in any case.
- `Linker`'s default store and the reservations are the package's tables, so a `LinkStorage` of the application's own
  with its own reservations is that application's to expire.

### Expiry warnings

- `Keys\ExpiryReport::report(?int $withinDays, ?Closure $each)` extends the report of `administration-events.md`. It
  lists, through `$each`, every key and certificate whose `not_after` is at or before the window, an expired one
  included, whatever was notified before, so a problem nobody has solved stays visible. The window is the days given,
  or the largest threshold. A retiring key whose overlap has ended, and one with no end of validity, are left out; so is
  a row whose connection is gone.
- It reads in pages of `PAGE_SIZE` (200) on the write connection, by keyset on (`not_after`, `id`), and each page's
  connections in one query. The answer, `Keys\ExpiryRun`, holds counts, so a run's memory does not grow with the keys.
- `sso.keys.expiry_thresholds` is a list of days, distinct, from 0 to 365, including 0: by default 30, 14, 7, 1 and 0.
  `Keys\ExpiryThresholds::reachedBy()` answers the most urgent one reached: one is reached when `not_after` is at or
  before now plus its days, so 0 is reached from the very second the validity ends.
- A key is warned of when the most urgent threshold it has reached is more urgent than `expiry_notified_threshold`, or
  it has none. So a run warns of one threshold at most, skipping any passed while nothing ran, and the warnings only
  escalate. A change of the thresholds is read by the next run and never brings back a less urgent warning. The warnings
  do not depend on the window: a narrow `--days` lists less and warns of the same keys.
- The delivery is **at least once**: a duplicate is possible, and a silent loss is not. `Keys\ExpiryNotifier`:
  1. in a short transaction, locks the connection and then the key, reads again whether the key is reportable, which
     threshold it has reached, whether it was warned of that or a more urgent one (`already_notified`), and whether
     another reporter's claim holds (`claimed`), and writes `expiry_claimed_until`, now plus
     `sso.keys.expiry_claim_seconds`;
  2. with that transaction closed, dispatches `Events\KeyNearingExpiry`, with the threshold in `thresholdDays`;
  3. only then records the marker, `expiry_notified_threshold` and `expiry_notified_at`, by one statement that only ever
     makes it more urgent, and releases the claim by another that matches its own end.
- The claim only limits how many reporters send at once. Its end also tells one claim from a later one, since a later
  claim is only taken once it has passed and always ends after it.
- A report refuses to run inside a transaction (a `LogicException`), since the dispatch must come before the marker and
  a transaction would hold it back until its commit.

### The audit of the other two commands

- `sso:domains:recheck` and `sso:metadata:refresh`, OIDC included, were audited against overlapping commands, duplicate
  queued jobs, worker death, expired leases and claims, takeover, administrative changes during a lookup or fetch, and an
  old worker writing after takeover. Their database coordination holds, and no behaviour changed. Since then, a domain
  recheck contains a resolver that throws (below).
- Idempotence here is of effects, not of activity. Overlapping metadata commands queue duplicate jobs, since neither has
  claimed anything; the duplicates apply nothing. A later domain recheck moves its successful-check time, as it should.

## Success Path

1. The application calls `OperationsSchedule::register()` from `withSchedule()`, and runs the scheduler on every server.
2. Each hour every server runs `sso:prune`. The first to reach a row deletes it; the others count nothing for it. Each
   logs its line and exits 0.
3. Each day every server runs `sso:keys:expiring`. One takes each key's claim, dispatches, and records; the others see
   `claimed` or `already_notified`. All print what is expiring or has expired.

## Failure / Edge Cases

- A reporter that dies after its claim leaves it to run out, and a later run sends the warning.
- A reporter that dies after its dispatch, or whose marker statement fails, has sent a warning a later run sends again.
- A dispatch that throws, which may have reached some listeners, releases the claim, records nothing, ends that key with
  `failed`, logs its exception's class, and goes on to the next key; the command exits non-zero. A later run sends it
  again.
- A key retired or removed after its claim may be warned of once more; the marker's statements then touch no row.
- A database error in the report propagates and stops it; the command exits non-zero by class alone.
- A reservation whose connection is gone is deleted, with no version to raise.
- A row renewed between the select and the delete stands: a pending claim re-claimed, a counter restarted, a single-use
  key recorded again.
- PostgreSQL `REPEATABLE READ` callers whose snapshot predates a pruned reservation fail to serialise on the raised
  `links_version`, rather than reason from what is gone.
- A resolver bound by the application should answer `lookup_failed` rather than throw, but a throw no longer stops the
  recheck run: the claim is left as it was but for its lease, which is released, it is reported as `resolver_threw`,
  never as a failed lookup, the exception is logged by its class alone, and the run goes on to the other claims, as
  `domain-rechecks.md` records. The command still exits non-zero, so monitoring notices. Only what the resolver throws
  is contained; a database error still stops the run.

## Implementation Anchors

- `src/Pruning/Pruner.php`, `src/Pruning/PruneTarget.php`, `src/Pruning/PruneSettings.php`, `src/Pruning/PruningCheck.php`,
  `src/Pruning/PruneReport.php`, `src/Pruning/PruneFailedException.php`, `src/Pruning/Enums/PruneKind.php`,
  `src/Pruning/Enums/PruneStatus.php`.
- `src/Links/ReservationWithdrawal.php`: `expired()`.
- `src/Keys/ExpiryReport.php`, `src/Keys/ExpiryNotifier.php`, `src/Keys/ExpiryThresholds.php`, `src/Keys/ExpiryRun.php`,
  `src/Keys/ExpiringKey.php`, `src/Keys/Enums/ExpiryNotice.php`.
- `src/Operations/OperationsSchedule.php`, `src/Operations/OperationsSettings.php`, `src/Operations/OperationsCheck.php`.
- `src/Console/PruneCommand.php`, `src/Console/ExpiringKeysCommand.php`.

## Authoritative Tests

- `tests/Feature/Pruning/PrunerTest.php`
- `tests/Feature/Pruning/PruneSettingsTest.php`
- `tests/Integration/Pruning/ConcurrentPrunersTest.php`
- `tests/Feature/Keys/ExpiryReportTest.php`
- `tests/Feature/Keys/ExpiryNotifierTest.php`
- `tests/Unit/Keys/ExpiryThresholdsTest.php`
- `tests/Integration/Pruning/PruningRacesTest.php`
- `tests/Integration/Keys/ConcurrentExpiryReportersTest.php`
- `tests/Integration/Keys/ExpiryReporterRacesTest.php`
- `tests/Feature/Operations/OperationsScheduleTest.php`
- `tests/Feature/Console/PruneCommandTest.php`
- `tests/Feature/Console/ExpiringKeysCommandTest.php`
- `tests/Feature/Metadata/RefreshAcrossServersTest.php`
- `tests/Feature/Console/RecheckDomainsCommandTest.php`
- `tests/Feature/Domains/DomainRecheckerTest.php`

## Change Triggers

Update this note when a kind is added to pruning or its eligibility changes, when a table's scan or index changes, when
the warning's delivery guarantee changes, or when a command's exit code changes.
