# Domain Rechecks

## Purpose

This note records how verified domains stay verified (SSO-3.3, SSO-11.12): the scheduled recheck that looks each
verified domain's TXT record up again, the lease that keeps several servers from checking one domain at once, the lock
order its writes follow, the immediate suspension of linking when a record goes, the grace period during which the
domain still routes discovery, the restoration and the lapse, and the events each reports (SSO-10.3 to SSO-10.5). How a
domain is claimed and first verified, and the predicates it is judged by, are in `domains.md`.

## Invariants

- `sso:domains:recheck` (`Console\RecheckDomainsCommand`) runs `Domains\DomainRechecker::recheckAll()` for no client
  (`new ClientContext(null, null)`, built by the command, so its events carry no IP address or user agent), which
  answers a `Domains\RecheckReport`: a `Domains\RecheckEntry` per claim it selected, in the order it checked them (the
  claim's id, its connection's id, the domain, a `Domains\Enums\RecheckOutcome` and, while a record failure is pending,
  when the domain lapses), with `count()` per outcome, `hasLookupFailures()` and `hasResolverThrows()`. Neither holds a
  token or a record's value; both encode with snake_case keys and times in UTC.
- Only verified claims are rechecked: a pending or lapsed claim is never selected and never leased. The claims are read
  on the write connection in chunks of `CHUNK_SIZE` (100), ordered by `last_successful_check_at` then `id` and paged by
  keyset on that pair (the `recheck_index`), never by offset and never all at once. A run selects only claims whose
  `updated_at` is before the instant it began, so a claim another server, or this run, has already written during the
  run is not selected again; the keyset cannot meet a claim twice either, since a confirmation moves its check time to
  now. A verified claim always has a successful check time (its verification sets it); one without is never selected.
- Each claim is first leased for `LEASE_SECONDS` (300) by one conditional update through the query builder, which does
  not stamp `updated_at`: only while the claim is verified, its `updated_at` is the one it was selected with, and its
  `recheck_leased_until` is empty or not after now. The update runs in a short transaction that first locks the
  claim's connection row, so even inside a transaction the application opened, the claim's row is never locked before
  its connection's. No row updated means `skipped`: another server holds the claim, or changed it since it was
  selected. Nothing else is done and nothing is reported.
- A claim whose `lapses_at` is set and not after now has run out of grace: it is lapsed without a lookup, even if its
  record has come back. Any other claim's record is looked up at `DomainStanding::lookupName()` through
  `Contracts\DnsResolver`, outside any transaction of the rechecker's own.
- A resolver that throws, which the contract forbids (it promises `lookup_failed` instead, and the package's own
  `SystemDnsResolver` never throws), is contained, and only the resolver's own call is: whatever it throws, `Error`s
  included, never reaches the run. The exception is logged once, as a warning, through `Logging\SanitizingLogger`
  (`sso.domains.recheck_resolver_threw`, with its class alone as `exception`: never its message, the domain or anything
  a provider said). Then the claim's lease is released, in a short transaction that locks the claim's connection first,
  by one statement through the query builder that sets `recheck_leased_until` to null only while it is still the exact
  lease this check took, so a server that took the claim over keeps its own. Nothing else is written: no lapse, no
  suspension, no failure count, no check time and no `updated_at`, so the row is as it was before the run. Nothing is
  reported, since `DomainRecheckFailed` would read as a failed lookup, which it is not. The entry is `resolver_threw`,
  with `lapsesAt` as the claim stood, and the run goes on to the next claim.
- The lease is released rather than left to expire, and the check time does not move, so the claim keeps its place as
  the least recently confirmed, and the next run (or an overlapping one, which selects it again since nothing was
  stamped) checks it first, with every other claim after it. A lease held past the next run would have that run skip it,
  reported as `skipped` rather than `resolver_threw`, hiding the fault from the exit code and delaying the confirmation
  once the resolver answers again.
- Repeated throws never lapse or suspend a domain. Like a failed lookup, they leave its last successful check where it
  was, so linking by the domain stops on its own once that check is older than the linking maximum age, while discovery
  still routes it. A claim already suspended keeps its lapse time, and lapses without a lookup once it has passed, as
  any claim past its grace does.
- The result is written in one transaction on the storage connection (retried up to three times on a deadlock when it
  is the outermost), which locks in the shared order: the connection's row by its id (a system job, scoped to no
  tenant), then the claim by (`connection_id`, `domain`) through `DomainFinder::find(..., true)`. Every read that
  decides the write is one of those locking reads; nothing locks by `verified_domain`. A connection gone, or a claim
  gone, replaced by another row, no longer verified or holding another token than the one looked up (compared in
  constant time), is `skipped`, its lease left to expire. So is a claim whose `recheck_leased_until` is no longer the
  exact lease this check wrote, or is not after now: a lookup that outlasted its lease may be older than what a server
  that took the claim over has since written (a suspension must never be lifted by an older answer).
- Under the locks, the claim read again decides the outcome:
  - Its grace has run out: it lapses (below).
  - The lookup failed (`lookup_failed`): nothing about the claim is written but the release of its lease; its check time
    does not move and no suspension starts. `DomainRecheckFailed` reports `lookup_failed` with `lapsesAt` as it stands,
    `null` unless an earlier check suspended it. A failed lookup is never read as a record gone or as a success, so
    linking by the domain stops on its own once its last successful check is older than the linking maximum age.
  - A record is exactly the token: `last_successful_check_at` becomes now and `verified_at` is kept. A suspended claim
    has `linking_suspended_at` and `lapses_at` cleared and is `restored` (`DomainRestored`, with the verification time
    kept and the check time); otherwise it is `confirmed` and nothing is reported.
  - No record (`record_absent`), or none that is exactly the token (`record_changed`): a claim not yet suspended has
    `DomainWithdrawal::linkingWithdrawn()` called, then `linking_suspended_at` set to now and `lapses_at` to now plus
    `recheck_grace_seconds`, read at that moment, so a later change to the setting never moves it (`suspended`); a claim
    already suspended keeps both times (`still_failing`). Either way `DomainRecheckFailed` reports the failure and the
    lapse time. When the lapse time is not after now (a grace period of 0), the claim lapses in the same transaction
    (`lapsed`, reporting `[DomainRecheckFailed, DomainLapsed]`).
- A lapse runs inside the transaction that holds the connection's and the claim's locks: it calls
  `DomainWithdrawal::linkingWithdrawn()` first, then sets `state` to `lapsed` and clears `verified_domain`,
  `verified_at`, `lapses_at`, `linking_suspended_at` and the lease, sets `lapsed_at` to now and keeps
  `last_successful_check_at` for display, then reports `DomainLapsed`. Clearing `verified_domain` frees the domain for
  another connection. The withdrawal deletes the domain's open link reservations
  (`Links\ReservationWithdrawal::ofDomain()`, raising the connection's `links_version`), so a lapse or a suspension can
  never leave one to be redeemed, and a code bound to one is `reservation_invalid`. A lapse without a lookup runs in its
  own such transaction, with the same locks.
- Every write goes through the model (`forceFill()->save()`), so `updated_at` is stamped from the clock, and releases
  the lease in the same save. A skip or an exception that stops the run leaves the lease to expire, at most
  `LEASE_SECONDS` later; a resolver that threw releases it, as above.
- Events are dispatched through `Administration\DomainEvents`, inside the transaction and after the write, so they reach
  listeners once it commits and never when it rolls back; a recheck's context names the connection, its tenant and
  protocol, and no acting identity.
- The recheck asks no freshness (no caller acts, and SSO-2.12 lists no recheck operation) and takes no rate-limit
  attempt. It holds nothing between runs (SSO-11.2); resolve it per run.
- The command prints `[<outcome>] <domain> (connection <id>)` for each entry other than `confirmed` and `skipped`, then
  `Domains rechecked:` and the count of each outcome, `resolver_threw` apart from `lookup_failed`. It exits 1 when a
  lookup failed, when the resolver threw, and when the run stopped on an exception, which it names by class alone;
  otherwise 0.

## Success Path

1. The scheduler runs `sso:domains:recheck` hourly on every server.
2. Each run selects the verified claims not changed since it began, least recently confirmed first.
3. For each, the first server to lease it looks its record up; the others skip it.
4. The record still carries the token: the check time moves to now, the verification time is kept, nothing is
   reported, and the domain keeps allowing linking for up to a day from this check.
5. A second run with the same DNS writes nothing new: a claim written since the run began is not selected, and a later
   run confirms the domain again without printing it.

## Failure / Edge Cases

- A record removed or replaced suspends linking at once, while discovery keeps routing until `lapses_at`; a record back
  within the grace period restores the domain; still gone at the end of it, the domain lapses at the next run.
- A domain lapsed is verified again with `DomainService::verify()`, and then counts from its new verification time and
  its new check, under a new `verification_generation`: a reservation bound to the old one never activates, and a
  membership must have been accepted before the new time, so a re-verification cannot capture people who joined since.
- A domain restored within the grace period keeps its verification time and generation; its reservations, deleted when
  it was suspended, do not come back.
- A claim removed, claimed again, given another token or no longer verified between the lookup and the transaction is
  skipped with nothing written or reported; a claim removed before its lease is taken leases nothing and is skipped.
- A server that dies mid-check leaves its lease to expire; the next run takes the claim over.
- A lookup that outlasts `LEASE_SECONDS` writes nothing (`skipped`), whether or not another server took the claim over
  meanwhile; the next run checks it again.
- If the grace period ran out during a lookup that finished within its lease, the claim is lapsed whatever the lookup
  answered.
- A resolver that throws on one claim is contained, and the run checks the rest; the command exits 1 so monitoring
  notices, and the warning logged names the exception's class.
- A database error, or anything else thrown but by the resolver (the package's own storage, the withdrawal, the
  settings), propagates (SSO-11.4) and stops the run, even when it is raised releasing the lease of a claim the resolver
  threw on; the claims already written stay written and reported. The command exits 1 naming the exception's class,
  never its message, which could carry a value read from the database or the DNS.
- A malformed `recheck_grace_seconds` fails closed with an `InvalidArgumentException` naming its key, before a
  suspension is written.

## Implementation Anchors

- `src/Domains/DomainRechecker.php`, `src/Domains/RecheckReport.php`, `src/Domains/RecheckEntry.php`,
  `src/Domains/Enums/RecheckOutcome.php`, `src/Console/RecheckDomainsCommand.php`.
- Shared with the domain helpers: `src/Domains/DomainFinder.php`, `DomainStanding.php`, `DomainSettings.php`,
  `DomainWithdrawal.php`, `DnsLookup.php`, `Enums/RecheckFailure.php`; `src/Links/ReservationWithdrawal.php`;
  `src/Administration/DomainEvents.php`; `src/Events/DomainRecheckFailed.php`, `DomainRestored.php`, `DomainLapsed.php`;
  `src/Models/Domain.php`.

## Authoritative Tests

- `tests/Feature/Domains/DomainRecheckerTest.php`, `tests/Feature/Console/RecheckDomainsCommandTest.php`.
- `tests/Unit/Domains/RecheckReportTest.php`, `tests/Unit/Domains/Enums/RecheckOutcomeTest.php`.
- `tests/Integration/Domains/ConcurrentDomainRechecksTest.php` (MySQL and PostgreSQL, plainly and inside a caller's
  transaction, and racing removals), `tests/Integration/Domains/DomainRecheckAfterCommitTest.php`.
- `tests/Feature/Linking/ReservationWithdrawalTest.php`, `tests/Integration/Linking/ConcurrentReservationTest.php`
  (a withdrawal racing a reservation).
- `tests/Performance/DomainRecheckQueryBudgetTest.php`.

## Change Triggers

- A change to which claims are selected, their order, the chunk size, or the lease and its conditions.
- A change to the lock order, to what is read again under the locks, or to what skips a claim.
- A change to what a confirmation, a suspension, a restoration, a failed lookup or a lapse writes or reports.
- A change to what is contained when the resolver throws, to how its lease is released, or to what is logged.
- A change to where `DomainWithdrawal` is called, or to what the lapse transaction does.
- A change to the command's output or exit codes.
