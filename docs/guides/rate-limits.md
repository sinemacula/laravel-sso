# Rate Limits

Every flow an attacker could drive at volume is rate limited, always: starting an authorisation request, a response at
a connection's assertion consumer service or callback, redeeming a handoff code, importing or refreshing a connection's
metadata, and checking a domain's DNS record. The attempts are counted in the database, so the limits hold across every
server and queue worker without a cache, and a full limit refuses the attempt as an outcome, `rate_limited`, with the
seconds to wait.

Every attempt counts, whether it then succeeds or fails, against every limit of its flow, all or none: when one limit
is full, the attempt counts against none of them.

## The settings

Each limit is `max` attempts (1 to 1000000) in each window of `decay_seconds` (1 to 86400, a day):

| Key                                                  | Default       | Counts each                                                     |
|------------------------------------------------------|---------------|-----------------------------------------------------------------|
| `rate_limits.authorization_request.per_ip`           | 30 per 60 s   | IP address starting authorisation requests                      |
| `rate_limits.authorization_request.per_email_domain` | 300 per 60 s  | email domain discovery is asked about                           |
| `rate_limits.completion.per_ip`                      | 30 per 60 s   | IP address posting to an assertion consumer service or callback |
| `rate_limits.completion.per_connection`              | 600 per 60 s  | connection receiving responses                                  |
| `rate_limits.redemption.per_ip`                      | 30 per 60 s   | IP address redeeming handoff codes                              |
| `rate_limits.metadata.per_connection`                | 10 per 3600 s | connection whose metadata or discovery document is fetched      |
| `rate_limits.domain_check.per_connection`            | 30 per 3600 s | connection whose domains' DNS records are checked               |

```php
// config/sso.php
'rate_limits' => [
    'table'      => env('SSO_RATE_LIMITS_TABLE', 'sso_rate_limits'),
    'connection' => env('SSO_RATE_LIMITS_CONNECTION'),

    'completion' => [
        'per_ip'         => ['max' => 30, 'decay_seconds' => 60],
        'per_connection' => ['max' => 600, 'decay_seconds' => 60],
    ],

    // ... every other flow, each with every one of its limits
],
```

The limits cannot be turned off. A limit that is missing, `null` or malformed (anything but exactly a `max` and a
`decay_seconds`, each an integer or a string of digits, within range) fails closed: every attempt at its flow throws an
`InvalidArgumentException` naming the key, and the boot check and `php artisan sso:check` report it under
`[rate_limits]`. A key the package does not count (a scope its flow is not counted in, such as `per_connection` under
`redemption`, or a flow it does not have) is reported too, since it would seem to limit something and limit nothing.
When you publish the config, keep every flow and every limit in it: the published `rate_limits` block replaces the
package's whole.

Windows are aligned to the clock: a 60-second window runs from the start of one minute to the next, whoever makes the
first attempt in it, and a full limit waits until its window ends.

## Choosing limits

- **Per IP address** limits stop one client hammering a flow. Size them for the busiest legitimate address you
  serve: an office or a mobile carrier behind one NAT address can start many sign-ins a minute. IPv6 clients are
  counted by their /64, and an IPv4 client reaching you over an IPv4-mapped or NAT64 address counts as its IPv4
  address. Behind a proxy or a load balancer, configure Laravel's trusted proxies, so the address counted is the
  client's and not the proxy's: every client behind one untrusted proxy would share one limit.
- **Per email domain** limits stop discovery being used to probe or flood one organisation's identity provider. Size
  them for the domain of your largest tenant at its busiest sign-in hour. The domain is counted case-insensitively,
  without a trailing dot, and in its ASCII form, so `Bücher.example` and `xn--bcher-kva.example` share one limit.
- **Per connection** limits on completions stop a flood of forged responses at one tenant's endpoint; size them for
  the tenant's peak sign-ins a minute. The metadata and domain check limits bound how often the package reaches out to
  a provider's or a domain's servers on the connection's behalf: the metadata limit counts each URL import naming the
  connection and each administrator's `MetadataRefresher::refreshNow()`, before anything is fetched. The scheduled
  domain recheck and the scheduled metadata refresh take no attempt, since no request drives them (see
  [Domain rechecks](domain-rechecks.md) and [SAML metadata](saml-metadata.md)).
- A refused attempt is not counted, so a client that keeps trying is never locked out for longer than the window.
  Shorter windows recover sooner; longer windows with a higher `max` tolerate bursts.

Changing a window's length keeps each counter's current window until it ends, and its earlier attempts still count,
so a change of configuration neither forgives nor loses attempts.

## The table and its connection

The counters live in one table, created by the published migration (see [Installation](installation.md)):

| Key                      | Default           | Env                          |
|--------------------------|-------------------|------------------------------|
| `rate_limits.table`      | `sso_rate_limits` | `SSO_RATE_LIMITS_TABLE`      |
| `rate_limits.connection` | `null`            | `SSO_RATE_LIMITS_CONNECTION` |

Each row holds a keyed digest of what it counts, made with your application key, so the table, a backup or a replica
gives back no IP address, email domain or connection id; rotating `APP_KEY` starts every counter afresh. The limiter
needs `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the table.

The counters live on the storage connection unless `rate_limits.connection` names their own. Name one when your flows
run inside transactions on the storage connection that may roll back: on a separate connection, an attempt is counted
whatever happens to the flow's transaction, so failing an attempt on purpose never uncounts it. The connection can be
the same database under another connection name. Set it before migrating: the migration creates the table on the
counters' connection, where the limiter reads and writes it.

Any database error (a missing table, a lost connection, a timeout) is thrown, and the flow fails as a server error: a
limiter that cannot count never lets an attempt through.

## Pruning

A counter whose window has ended is restarted by its next attempt, but its row stays until it is pruned, which
`sso:prune` does along with everything else the package no longer needs: see [Operations](operations.md#pruning).
Laravel's `model:prune` works too, and takes the same rows, naming the package's model, since it lives outside your
`app/Models`:

```php
use Illuminate\Support\Facades\Schedule;
use SineMacula\Laravel\Sso\Models\RateLimit;

Schedule::command('model:prune', [
    '--model' => [RateLimit::class],
])->hourly();
```

Each chunk is one conditional `DELETE` of counters whose window has ended by the package's clock (see
[Clock](clock.md)). Pruning never touches a live window, and changes nothing about what the limiter answers: it only
keeps the table small. To see how many counters would go:

```bash
php artisan model:prune --model="SineMacula\Laravel\Sso\Models\RateLimit" --pretend
```

## Answering a rate limited attempt

The package's flows count each attempt before they do any work, and a refused one is an outcome, never an exception:
its result has the reason `rate_limited` and `retryAfter`, the whole seconds (at least one) until the full limit's
window ends, and the flow emits its one failure event with `rate_limited` (see [Events](events.md)). Answer it with
HTTP 429 and a `Retry-After` header:

```php
if ($result->isRateLimited()) {
    return response()->json(['error' => 'rate_limited'], 429, [
        'Retry-After' => (string) $result->retryAfter,
    ]);
}
```

The same check is available directly, through the contract, for anything of your own that drives a limited flow:

```php
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

$result = app(AttemptLimiter::class)->attempt(
    AttemptSubject::authorizationRequest($request->ip(), $emailDomain),
);
```

Each flow has its own constructor (`authorizationRequest`, `completion`, `redemption`, `metadata`, `domainCheck`),
naming only what that flow counts. Pass the IP address and the email domain as received; the limiter counts each in
its canonical form. A `null` IP address (a console command) or email domain (no discovery) is not counted.

## Binding another limiter

Bind your own implementation of `AttemptLimiter` (in a service provider's `register()`) only if it gives every
guarantee the default does: every attempt counted, all or none, atomically and shared by every server; a full limit
answered `rate_limited` with the seconds until it frees, and nothing counted; every limit always on; and any error
thrown, never an attempt let through uncounted. Bind it scoped, not as a singleton, if it holds anything from one
request or job to the next.
