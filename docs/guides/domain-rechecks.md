# Domain Rechecks

A domain stays verified only while its TXT record does. `php artisan sso:domains:recheck` looks the record of every
verified domain up again: a record that still carries the token keeps the domain verified, and one that has gone
suspends linking by it at once and, after a grace period, lapses it. See [Domains](domains.md) for claiming and
verifying a domain.

## Scheduling it

Run it from the scheduler, hourly, which [the operations schedule](operations.md) does for you along with the other
commands, or on its own:

```php
// bootstrap/app.php
use Illuminate\Console\Scheduling\Schedule;

->withSchedule(function (Schedule $schedule): void {
    $schedule->command('sso:domains:recheck')->hourly();
})
```

It is idempotent and safe on several servers at once: each domain is leased by one server for the check, and the
others skip it, so you do not need `onOneServer()`. A domain written since a run began is not checked again by that
run.

> [!IMPORTANT]
> Linking by email (SSO-8.8) stops 24 hours after a domain's last successful check, whatever the schedule, so a stopped
> scheduler cannot keep it going: `sso.domains.linking_max_age_seconds` sets a shorter age, never a longer one. Schedule
> the recheck well inside that age; hourly leaves room for a few failed runs.

## What a check does

| Outcome         | When                                                                    | What changes                                                     | Event                 |
|-----------------|-------------------------------------------------------------------------|------------------------------------------------------------------|-----------------------|
| `confirmed`     | A record at the name is exactly the token                               | The last successful check is now; the verification time is kept  | None                  |
| `restored`      | The same, for a domain whose record had gone, within the grace period   | Linking resumes, and the domain no longer lapses                 | `DomainRestored`      |
| `suspended`     | No record, or none that is exactly the token                            | Linking stops at once; the domain lapses at the end of the grace | `DomainRecheckFailed` |
| `still_failing` | The record is still gone, within the grace period                       | Nothing: the suspension and the lapse time are kept              | `DomainRecheckFailed` |
| `lapsed`        | The grace period has run out, or is 0                                   | The domain is no longer verified, and is free for another tenant | `DomainLapsed`        |
| `lookup_failed` | The resolver could not answer                                           | Nothing                                                          | `DomainRecheckFailed` |
| `skipped`       | Another server is checking it, or it changed while it was being checked | Nothing                                                          | None                  |

While the grace period runs (`sso.domains.recheck_grace_seconds`, three days by default), discovery still routes the
domain to its connection, so a record removed by mistake does not lock people out; only linking by email stops, at
once. With a grace period of 0, one run suspends and lapses the domain, reporting `DomainRecheckFailed` then
`DomainLapsed`. The time the domain lapses is fixed when its record is first found gone: changing the setting afterwards
does not move it. A domain past its grace lapses at the next run even if its record has come back; verify it again with
`DomainService::verify()`, and it then counts from its new verification time.

A failed lookup proves nothing either way, so it changes nothing: the domain is not suspended, and its last successful
check does not move, so linking by it stops on its own once that check is older than the linking maximum age.

`DomainRecheckFailed` carries `failure` (`record_absent`, `record_changed` or `lookup_failed`) and `lapsesAt`. No event
carries the token or a record's value. Each is dispatched after the check's transaction commits; see
[Events](events.md).

## Output and exit codes

The command prints a line for each domain that did more than confirm, then the count of each outcome:

```text
[suspended] example.com (connection 01jbx3k5d2r9w8v7t6s5q4p3n2)
[lookup_failed] example.org (connection 01jbx3k5d2r9w8v7t6s5q4p3n2)
Domains rechecked: confirmed 41, restored 0, suspended 1, still_failing 0, lapsed 0, lookup_failed 1, skipped 0
```

It exits `1` when any lookup failed, so a resolver that cannot answer is noticed, and when the run stopped on an
exception (a database error, or a resolver that threw), which it names by its class alone; otherwise `0`. A run stopped
part way keeps what it had already written; the domain it was checking is picked up again once its lease expires,
after five minutes.

## The DNS resolver

The recheck looks records up through the same `DnsResolver` as a verification. The default, the system resolver, has no
timeout of its own, so a slow resolver holds the command for as long as the system allows; bind your own for a bounded
deadline (see [Domains](domains.md#the-dns-resolver)).

## Running it from code

```php
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;

$report = app(DomainRechecker::class)->recheckAll();

$report->hasLookupFailures();       // bool
$report->count(RecheckOutcome::SUSPENDED);
json_encode($report);               // entries and counts, snake_case, times in UTC
```

Resolve it per run. It asks no freshness and takes no rate-limit attempt: it is a system job, acting for no tenant.

## Testing

Bind `SineMacula\Laravel\Sso\Testing\FakeDnsResolver` and answer each verified domain's record name:

```php
$this->app->instance(DnsResolver::class, $dns = new FakeDnsResolver);

$dns->absent('_sso-verification.example.com');

$this->artisan('sso:domains:recheck')->assertExitCode(0);
```
