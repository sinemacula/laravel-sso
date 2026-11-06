# Rate Limits

## Purpose

This note records how the package limits each flow an attacker could drive at volume (SSO-11.8): which flows and
scopes are counted, how a counter is keyed so the table gives nothing back, the canonical forms values are counted in,
how a count changes atomically across servers, why an attempt counts against every limit or none, why the limits are
always on, why the counters may live on a connection of their own, and how a full limit is answered.

## Invariants

- `Contracts\AttemptLimiter::attempt($subject)` takes a `RateLimiting\AttemptSubject`, built only through the named
  constructor of its flow, and answers a `RateLimiting\AttemptResult`: `allowed`, counted against every limit the
  subject names; or `rate_limited` (`FailureReason::RATE_LIMITED`) with `retryAfter`, the seconds (at least one) until
  the full limit's window ends, and nothing counted. Throttling is an outcome, never an exception (see `outcomes.md`).
- The flows and the scopes each is counted in are fixed by `RateLimiting\Enums\AttemptFlow::scopes()`:

  | Flow                    | What it is                                               | Scopes                       |
  |-------------------------|----------------------------------------------------------|------------------------------|
  | `authorization_request` | Starting an authorisation request                        | `per_ip`, `per_email_domain` |
  | `completion`            | A response at an assertion consumer service or callback  | `per_ip`, `per_connection`   |
  | `redemption`            | Redeeming a handoff code                                 | `per_ip`                     |
  | `metadata`              | Importing or refreshing metadata or a discovery document | `per_connection`             |
  | `domain_check`          | Checking a domain's DNS record                           | `per_connection`             |

- The IP address is the one of the `Http\ClientContext` the action was given (`AttemptSubject::authorizationRequest()`,
  `completion()` and `redemption()` take the context itself). A `null` IP address (a client with none, as a console
  command passes) or email domain (no discovery) is not counted: `AttemptSubject::counted()` leaves it out. The
  connection of a flow counted by connection is always given.
- Every limit is always on. `RateLimiting\AttemptLimits` reads `sso.rate_limits.<flow>.<scope>` on every call, each
  exactly `['max' => int, 'decay_seconds' => int]`, `max` from 1 to 1000000 and `decay_seconds` from 1 to 86400 (an
  integer, or the canonical decimal string `env()` returns). A limit that is missing, `null` or malformed throws an
  `InvalidArgumentException` naming its key; nothing falls back to a literal, and nothing turns a limit off. The limiter
  reads every limit of the flow before it counts anything, so a malformed limit fails closed and counts nothing, even
  for a scope the subject gives no value for.
- Windows are aligned to the Unix epoch: `AttemptLimit::windowEnd($now)` is the first multiple of `decay_seconds`
  after `$now`. Every server computes the same window for the same second without reading it back.
- A counter's key is a keyed digest (`RateLimiting\CounterKeys`): the lower-case hex HMAC-SHA256 of the flow, the scope
  and the value in its canonical form, joined by NUL bytes, under a key derived from the application key (`app.key`)
  for this purpose alone. What a counter counts is easy to enumerate, so a plain digest could be reversed from a backup
  or a replica by hashing every candidate; the keyed digest cannot be recomputed without the application key, and stays
  deterministic, so every server counts in the same row. A missing `app.key` throws. Rotating it starts every counter
  afresh.
- Values are counted in their canonical form, so a client cannot spread its attempts over several counters by writing
  one value another way:
  - an IP address: an IPv4 address in dotted decimal; an IPv4-mapped (`::ffff:0:0/96`) or NAT64 (`64:ff9b::/96`) IPv6
    address as the IPv4 address it carries; any other IPv6 address as its /64 network, since a client usually controls
    a whole /64; a value that is not an IP address, lower-cased as given;
  - an email domain: lower-cased, one trailing dot removed, converted to ASCII by IDNA (UTS 46, non-transitional), so
    `Bücher.example` and `xn--bcher-kva.example` share a counter; a value that will not convert, lower-cased as given;
  - a connection id: as given.
- Counts change only through single statements on the counters' connection, always on its write PDO
  (`RateLimiting\RateLimitStore`), so concurrent attempts on any number of servers never read a count, add to it and
  write it back over each other. Taking a slot is an `UPDATE` that restarts an ended window with this attempt, or
  increments the window that ends at the computed end while it has room; then an insert that ignores a duplicate key;
  then the `UPDATE` once more. A live counter whose stored window does not end at the computed end (started under
  another `decay_seconds`, or by a server whose clock is ahead) is read on the write PDO and counted in its own window,
  by one conditional increment, while that window has room. `take()` answers the window it took a slot from, or, when
  the window is full, the Unix time it ends.
- All or none: the limiter takes a slot from each counter in the order of `AttemptFlow::scopes()`. When one is full,
  every slot taken before it is given back, each only to the window it was taken from and only while it holds an
  attempt, and the attempt is refused with `max(1, windowEnd - now)`. A give-back never touches a later window, and a
  refused attempt is counted nowhere.
- Database errors propagate. The store and the limiter catch nothing, so a limiter that cannot count never lets an
  attempt through (SSO-11.4); the flow fails as a server error.
- The counters live in `sso.rate_limits.table` (default `sso_rate_limits`) on `sso.rate_limits.connection`, or the
  storage connection when that names none (`Database\StorageConnection::connectionFor('rate_limits.table')`). The model,
  the store and the migration resolve the same connection. A separate connection exists because a flow may run inside
  a transaction on the storage connection that rolls back when the flow is refused: on the storage connection, the
  attempt is rolled back with it, so a refused attempt would cost an attacker nothing; on a connection of their own, it
  is counted whatever happens to the flow's transaction.
- Times are whole seconds in UTC, whatever the application timezone, written and read through
  `Models\Casts\UtcDateTime`. The column holds no offset, so in a timezone with daylight saving the hour a fall-back
  repeats would name two instants with one value, and a live window could read as ended, letting every attempt restart
  the count. Every time is read from the one bindable clock (`Contracts\Clock`, SSO-11.13).
- The limiter, the store, the keys and the limits hold nothing between calls, and the limiter is bound scoped
  (SSO-11.2).

## Success Path

- An attempt below every limit of its flow takes one slot from each counter it names and answers `allowed`.
- The first attempt in a window creates the counter with one attempt; the first attempt after the window has ended
  restarts it with one attempt.
- `sso:prune` (`operations.md`), and `model:prune` on `Models\RateLimit`, delete the counters whose window has ended by
  the package's clock (`window_ends_at <= now`); the next attempt would restart them anyway, so pruning only keeps the
  table small.

## Failure / Edge Cases

- An attempt at a full limit answers `rate_limited` with the seconds until that window ends, at least one, and counts
  nothing anywhere: with `per_ip` full and `per_email_domain` free, the domain's counter is not touched; with the
  domain full, the IP address's slot is given back.
- Flows and scopes are counted apart: a full limit on one flow or scope refuses nothing on another.
- A change of `decay_seconds` keeps each counter's stored window until it ends, its attempts still counted, and a slot
  taken from that window is given back to it.
- A counter created by another request between this one's `UPDATE` and its insert is counted by the second `UPDATE`.
- A counter pruned, or whose window ended, between the statements and the read answers `rate_limited` with one second:
  the attempt is refused rather than counted without a statement that took its slot.
- A stored window filled by another request before the read, or between the read and the increment, refuses the
  attempt until it ends, and the count never passes `max`.
- A limit missing, `null` or malformed throws at every attempt of its flow, and `[rate_limits]` reports it at boot and
  in `sso:check`. A key the package does not count (a scope under a flow that is not counted in it, such as
  `redemption.per_connection`, or a flow the package does not have) is reported too, since it would seem to limit
  something and limit nothing.
- A missing table, a dropped connection, a timeout or any other database error is thrown (`QueryException`).
- Another bound limiter must count every attempt against every limit its subject names, all or none, atomically and
  shared by every server; refuse a full limit with the seconds until it frees, counting nothing; keep every limit
  always on; throw on any error, never letting an attempt through uncounted; and keep no raw IP address, email domain
  or connection id where a reader of its store could recover it.

## Implementation Anchors

- `src/Contracts/AttemptLimiter.php`; `src/RateLimiting/AttemptSubject.php`; `src/RateLimiting/AttemptResult.php`;
  `src/RateLimiting/Enums/AttemptFlow.php`; `src/RateLimiting/Enums/AttemptScope.php`.
- `src/RateLimiting/DatabaseAttemptLimiter.php`: `attempt()`, `counters()`, `giveBack()`.
- `src/RateLimiting/RateLimitStore.php`: `take()`, `giveBack()`, `writeCount()`, `storeNewCounter()`,
  `takeFromStoredWindow()`, `countIn()`.
- `src/RateLimiting/CounterKeys.php`: `counter()`, `canonicalIp()`, `canonicalDomain()`, `secret()`.
- `src/RateLimiting/AttemptLimits.php` and `src/RateLimiting/AttemptLimit.php`: `for()`, `validate()`, `windowEnd()`.
- `src/RateLimiting/RateLimitsCheck.php`: the `[rate_limits]` check.
- `src/Models/RateLimit.php`: `prunable()`; `src/Models/Casts/UtcDateTime.php`.
- `database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php`.
- `src/SsoServiceProvider.php`: the `scopedIf` binding of `AttemptLimiter` and the `rate_limits` check.

## Authoritative Tests

- `tests/Unit/RateLimiting/AttemptLimitTest.php`
- `tests/Unit/RateLimiting/CounterKeysTest.php`
- `tests/Unit/RateLimiting/AttemptSubjectTest.php`
- `tests/Unit/RateLimiting/AttemptResultTest.php`
- `tests/Feature/RateLimiting/AttemptLimitsTest.php`
- `tests/Feature/RateLimiting/DatabaseAttemptLimiterTest.php`
- `tests/Feature/RateLimiting/RateLimitsCheckTest.php`
- `tests/Feature/Models/RateLimitTest.php`
- `tests/Integration/RateLimiting/RateLimitsMigrationTest.php`
- `tests/Integration/RateLimiting/CountersConnectionTest.php`
- `tests/Integration/RateLimiting/ConcurrentDatabaseAttemptLimiterTest.php` (MySQL and PostgreSQL; skipped on SQLite)
- `tests/Performance/AttemptLimiterQueryBudgetTest.php`: the statements of each path, per counter, and that each is
  data manipulation only.

## Change Triggers

- A new limited flow or scope, or a flow that counts a different value: its subject constructor, its canonical form,
  its configuration key and its default.
- Any change to the table's columns or indexes, to how windows are aligned, stored or compared, or to the statements
  that take and give back a slot.
- Any change to how a counter's key is derived, or to the canonical forms (every counter starts afresh).
- A limiter that counts through a cache, a read replica or a read-modify-write, or that catches a store error.
