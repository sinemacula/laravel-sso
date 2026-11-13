# Fresh authentication

Before each change that could widen or redirect access to a tenant, or destroy it (trusting a new certificate, enabling
a connection, claiming a domain, turning enforcement on, linking an identity), the package asks whether the caller
authenticated recently enough. It asks one contract, `SineMacula\Laravel\Sso\Contracts\Freshness`, with the operation's
stable name, the maximum age of the caller's authentication that operation requires, in seconds, and the caller the
change is made for. Only a `fresh` answer lets the change write; on `stale` the helper writes nothing, reports nothing,
and answers the failure reason `freshness_required`, so your application can ask the caller to authenticate again and
retry.

## Why the default refuses

The package cannot know how your application authenticates its callers, so its default contract,
`Freshness\RefusingFreshness`, answers `stale` for every operation. Until you bind a contract of your own, every change
listed below is refused with `freshness_required`. This is deliberate: a default that let changes through would let a
stolen session or a forgotten unlocked screen re-point a tenant's sign-in at an identity provider of the attacker's
choosing.

Reading connections, listing them and every sign-in flow are unaffected: only the changes below ask.

> [!NOTE]
> Under `laravel-iam` there is nothing to bind: it binds the contract to `laravel-authentication`'s freshness check,
> passing each operation's maximum age on as the caller's requirement, so an administrator is asked to authenticate
> again exactly as for the application's own sensitive changes. The stricter of that requirement and any
> freshness the application configures for the operation's name applies, so the package's maximum age holds where the
> application configures none. See [Integrating with `laravel-iam`](integrating-with-laravel-iam.md#freshness).

## Operations and their maximum ages

Each operation has its own maximum age, configured under `freshness.max_age_seconds` by its key: the name after
`sso.`, with the dots as underscores. Every one ships at `300` seconds (five minutes):

| Operation                      | What it guards                                                                                                                                                                                      | Config key                 | Default |
|--------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------|---------|
| `sso.connection.trust`         | Creating a connection, or changing its certificates, issuer or entity id, endpoints, client id or secret, subject settings, accepted signatures and algorithms, linking settings or evidence policy | `connection_trust`         | `300`   |
| `sso.connection.enable`        | Enabling a connection                                                                                                                                                                               | `connection_enable`        | `300`   |
| `sso.connection.disable`       | Disabling a connection                                                                                                                                                                              | `connection_disable`       | `300`   |
| `sso.connection.delete`        | Deleting a connection                                                                                                                                                                               | `connection_delete`        | `300`   |
| `sso.connection.idp_initiated` | Turning IdP-initiated sign-in on or off, or changing where it sends the browser                                                                                                                     | `connection_idp_initiated` | `300`   |
| `sso.keys.rotate`              | Adding, making current or retiring a service provider key and its certificate                                                                                                                       | `keys_rotate`              | `300`   |
| `sso.domain.claim`             | Claiming a domain for a connection                                                                                                                                                                  | `domain_claim`             | `300`   |
| `sso.domain.verify`            | Verifying a claimed domain                                                                                                                                                                          | `domain_verify`            | `300`   |
| `sso.domain.remove`            | Removing a domain from a connection                                                                                                                                                                 | `domain_remove`            | `300`   |
| `sso.enforcement.update`       | Turning enforcement on or off, or changing which connections satisfy it                                                                                                                             | `enforcement_update`       | `300`   |
| `sso.link.create`              | Starting a `link` flow for an authenticated identity                                                                                                                                                | `link_create`              | `300`   |
| `sso.link.remove`              | Removing a link                                                                                                                                                                                     | `link_remove`              | `300`   |

This published file keeps a trust change at five minutes, holds a key rotation to two, and leaves every other operation
at the default:

<!-- snippet: tests/Integration/Examples/Freshness/config/sso.php#freshness-max-ages -->
```php
// config/sso.php
'freshness' => [
    'max_age_seconds' => [
        'connection_trust' => 300,
        'keys_rotate'      => 120,
    ],
],
```

An age is a whole number of seconds from `1` to `3600` (an hour); a key you leave out takes `300`. Anything else (`0`,
more than `3600`, a fraction, a word, an empty value) fails closed when a change reads it, with
`sso.freshness.max_age_seconds.<key> must be an integer from 1 to 3600.`, and stops the boot outside the console. A key
that names no operation (`connection_trusted`, say, which would leave `connection_trust` at its default) is reported
too; `php artisan sso:check` lists both under `[freshness]`. The names are stable: none is renamed or reused once
released, so a policy keyed on them keeps working across upgrades.

A change that is several operations at once (a trust change that also turns IdP-initiated sign-in on) asks about each,
once, and is refused at the first that is `stale`.

## The caller

Every change that asks takes the caller it is made for as its own argument, an `Identities\Caller`: the identity your
application authenticated and, when you supply it, the session they are on, an opaque id of 1 to 255 bytes (anything
else is an `InvalidArgumentException`). The package passes that same caller to the contract, and names its identity
as the acting identity on the event the change reports; the session is never carried by an event. Build it where your
controller reads the request:

```text
new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $request->session()->getId())
```

No caller (`null`, the default) means no authenticated person, as for a scheduled job or a console command, and a
caller with no session means you supplied none, never "the current session". The package never reads the request, the
job or the session itself.

## Binding your own contract

Implement `Contracts\Freshness` and bind it in a service provider. `check()` is given the operation, its maximum age
and the caller; answer `fresh` only when that caller, on the session given, authenticated no more than that many
seconds ago, and `stale` otherwise, including for no caller and for a caller you cannot judge (one with no session,
when you judge sessions, or a session that is not theirs). Judge the caller you are given, never the request or job
being served. Never answer `fresh` when you cannot tell; let an error you cannot answer through propagate.

This one, `RecentSignInFreshness`, a `final readonly` class implementing `Contracts\Freshness`, reads the time the
caller's session last authenticated, a Unix timestamp your sign-in records against the session and its identity (here
`SignInTimes`, standing in for your sessions table), and compares its age with the maximum age. It takes that record
and the package's `Contracts\Clock`, so tests can move the time it reads, and answers a
`Freshness\Enums\FreshnessOutcome`:

<!-- snippet: tests/Integration/Examples/Freshness/RecentSignInFreshness.php#recent-sign-in-freshness -->
```php
/**
 * Take the application's record of sign-ins and the package's clock.
 *
 * @param  \Tests\Integration\Examples\Freshness\SignInTimes  $signIns
 * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
 */
public function __construct(

    /** When each session last authenticated, as the sign-in recorded it. */
    private SignInTimes $signIns,

    /** The package's clock, which a test can move. */
    private Clock $clock,
) {}

/**
 * Whether the caller authenticated within the maximum age.
 *
 * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
 * @param  int  $maxAgeSeconds
 * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
 * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
 */
#[\Override]
public function check(FreshnessOperation $operation, int $maxAgeSeconds, ?Caller $caller): FreshnessOutcome
{
    // Every operation is judged alike: a stricter policy would match on
    // the operation's stable name, $operation->value
    unset($operation);

    // No caller, or one on no session, cannot be judged
    if ($caller?->sessionId === null) {
        return FreshnessOutcome::STALE;
    }

    // The caller's own session, never the request being served
    $authenticatedAt = $this->signIns->authenticatedAt($caller->identity, $caller->sessionId);

    if ($authenticatedAt === null) {
        return FreshnessOutcome::STALE;
    }

    $age = $this->clock->now()->getTimestamp() - $authenticatedAt;

    return $age >= 0 && $age <= $maxAgeSeconds ? FreshnessOutcome::FRESH : FreshnessOutcome::STALE;
}
```

Bind it in a service provider's `register()`:

<!-- snippet: tests/Integration/Examples/Freshness/AppServiceProvider.php#freshness-binding -->
```php
$this->app->singleton(Freshness::class, RecentSignInFreshness::class);
```

One bound in a provider that registers before the package's is kept; one bound later replaces the default as any later
binding does. The package resolves the contract on every question, so a contract bound with `scoped()` is rebuilt for
each request. Whichever you choose, under Octane or a queue worker it judges the caller each call is given and keeps
nothing of one request or job for the next. A timestamp in the future, or one your application cannot vouch for, is
`stale`. If you key a stricter policy on the operation (asking for a second factor before `sso.connection.trust`, say),
match on its stable name, never on its position.

## The order every change follows

Each change finds what it changes and validates what it was given; then, in one transaction on the storage connection,
it takes its locks, asks the contract, and only then writes, reporting the change inside it. So a refusal never leaves
a partial change or an event behind, and your contract is asked after the locks the package takes for the change: it
may lock the caller's session row there, with a current read, and keep that lock until the change commits.

Verifying a domain, adding a key and refreshing metadata also ask once before their DNS lookup, key generation or
fetch, when no transaction is open, so a stale caller spends none of them; the answer under the locks still decides.
Answer each question afresh: a transaction retried after a deadlock asks again.

## Testing with `FakeFreshness`

`SineMacula\Laravel\Sso\Testing\FakeFreshness` answers what your test tells it and records every question with its
maximum age and caller. Bind it in place of the contract, run the change, then assert what was asked. Here it answers
`stale` for deleting alone, so a connection is enabled and its deletion is refused:

<!-- snippet: tests/Integration/Examples/Freshness/FreshnessExampleTest.php#fake-freshness -->
```php
$freshness = FakeFreshness::fresh()->staleFor(FreshnessOperation::CONNECTION_DELETE);

$this->instance(Freshness::class, $freshness);

self::assertTrue(app(ConnectionService::class)->enable(self::TENANT, $connectionId, $client)->isSucceeded());
self::assertSame(FailureReason::FRESHNESS_REQUIRED, app(ConnectionLifecycle::class)->delete(self::TENANT, $connectionId, $client)->reason);

$freshness->assertAsked(FreshnessOperation::CONNECTION_ENABLE, 300);
$freshness->assertAskedExactly([FreshnessOperation::CONNECTION_ENABLE, FreshnessOperation::CONNECTION_DELETE]);
```

`$client` is the `Http\ClientContext` of the request the call is made for, which your controller builds with
`ClientContext::fromRequest($request)`; work with no request (a console command, a queued job) passes
`new ClientContext(null, null)`. Every call that counts an attempt or reports an event takes one, never reading the
request itself, and each event it reports carries the client's IP address and user agent.

| Method                                                                   | What it does                                                                                    |
|--------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| `new FakeFreshness(FreshnessOutcome $outcome = FreshnessOutcome::FRESH)` | Answers the outcome given for every operation                                                   |
| `FakeFreshness::fresh()`, `FakeFreshness::stale()`                       | Answers `fresh`, or `stale`, for every operation                                                |
| `staleFor(FreshnessOperation ...$operations)`                            | Answers `stale` for the operations given and `fresh` for every other; a later call adds to them |
| `asked()`                                                                | Every question, in order, as `['operation' => ..., 'max_age_seconds' => ..., 'caller' => ...]`  |
| `assertAsked(FreshnessOperation $operation, ?int $maxAgeSeconds = null)` | Fails unless the operation was asked about, with the maximum age when one is given              |
| `assertAskedExactly(array $operations)`                                  | Fails unless exactly those operations were asked about, in that order                           |
| `assertNotAsked(?FreshnessOperation $operation = null)`                  | Fails if the operation was asked about or, with none given, if anything was                     |

Each fake holds its own answers and questions, so bind a new one in each test. It judges no caller: never bind it
outside your tests.
