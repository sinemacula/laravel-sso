# Fresh authentication

Before each change that could widen or redirect access to a tenant, or destroy it (trusting a new certificate, enabling
a connection, claiming a domain, turning enforcement on, linking an identity), the package asks whether the caller
authenticated recently enough. It asks one contract, `SineMacula\Laravel\Sso\Contracts\Freshness`, with the operation's
stable name and the maximum age of the caller's authentication that operation requires, in seconds. Only a `fresh`
answer lets the change write; on `stale` the helper writes nothing, reports nothing, and answers the failure reason
`freshness_required`, so your application can ask the caller to authenticate again and retry.

## Why the default refuses

The package cannot know how your application authenticates its callers, so its default contract,
`Freshness\RefusingFreshness`, answers `stale` for every operation. Until you bind a contract of your own, every change
listed below is refused with `freshness_required`. This is deliberate: a default that let changes through would let a
stolen session or a forgotten unlocked screen re-point a tenant's sign-in at an identity provider of the attacker's
choosing.

Reading connections, listing them and every sign-in flow are unaffected: only the changes below ask.

> [!NOTE]
> Under `laravel-iam` there is nothing to bind: it binds the contract to `laravel-authentication`'s freshness check
> (AUTH-3.11), passing each operation's maximum age on as the caller's requirement, so an administrator is asked to
> authenticate again exactly as for the application's own sensitive changes.

## Operations and their maximum ages

Each operation has its own maximum age, configured under `freshness.max_age_seconds` by its key: the name after
`sso.`, with the dots as underscores. Every one ships at `300` seconds (five minutes):

| Operation                      | What it guards                                                                                                                                                    | Config key                 | Default |
|--------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------|---------|
| `sso.connection.trust`         | Creating a connection, or changing its certificates, issuer or entity id, endpoints, client id or secret, subject settings, or accepted signatures and algorithms | `connection_trust`         | `300`   |
| `sso.connection.enable`        | Enabling a connection                                                                                                                                             | `connection_enable`        | `300`   |
| `sso.connection.disable`       | Disabling a connection                                                                                                                                            | `connection_disable`       | `300`   |
| `sso.connection.delete`        | Deleting a connection                                                                                                                                             | `connection_delete`        | `300`   |
| `sso.connection.idp_initiated` | Turning IdP-initiated sign-in on or off, or changing where it sends the browser                                                                                   | `connection_idp_initiated` | `300`   |
| `sso.keys.rotate`              | Adding, making current or retiring a service provider key and its certificate                                                                                     | `keys_rotate`              | `300`   |
| `sso.domain.claim`             | Claiming a domain for a connection                                                                                                                                | `domain_claim`             | `300`   |
| `sso.domain.verify`            | Verifying a claimed domain                                                                                                                                        | `domain_verify`            | `300`   |
| `sso.domain.remove`            | Removing a domain from a connection                                                                                                                               | `domain_remove`            | `300`   |
| `sso.enforcement.update`       | Turning enforcement on or off, or changing which connections satisfy it                                                                                           | `enforcement_update`       | `300`   |
| `sso.link.create`              | Starting a `link` flow for an authenticated identity                                                                                                              | `link_create`              | `300`   |
| `sso.link.remove`              | Removing a link                                                                                                                                                   | `link_remove`              | `300`   |

```php
'freshness' => [
    'max_age_seconds' => [
        'connection_trust' => 300,
        'keys_rotate'      => 120,
        // ...
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

## Binding your own contract

Implement `Contracts\Freshness` and bind it in a service provider. `check()` is given the operation and its maximum
age; answer `fresh` only when the caller of the request or job being served authenticated no more than that many
seconds ago, and `stale` otherwise, including when there is no caller you can judge (a queued job, a console command).
Never answer `fresh` when you cannot tell; let an error you cannot answer through propagate.

This one reads the time the caller last authenticated (a Unix timestamp your sign-in stores in the session, or the
`auth_time` of a verified token that your middleware puts on the request) and compares its age with the maximum age,
reading the time from the package's clock so tests can move it:

```php
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;

final readonly class RecentSignInFreshness implements Freshness
{
    public function __construct(
        private Container $container,
        private Clock $clock,
    ) {}

    public function check(FreshnessOperation $operation, int $maxAgeSeconds): FreshnessOutcome
    {
        // The request being served, resolved on each call and never held
        $request = $this->container->make(Request::class);

        if ($request->user() === null) {
            return FreshnessOutcome::STALE;
        }

        $authenticatedAt = $request->hasSession()
            ? $request->session()->get('auth.authenticated_at')
            : $request->attributes->get('auth_time');

        if (!is_int($authenticatedAt)) {
            return FreshnessOutcome::STALE;
        }

        $age = $this->clock->now()->getTimestamp() - $authenticatedAt;

        return $age >= 0 && $age <= $maxAgeSeconds ? FreshnessOutcome::FRESH : FreshnessOutcome::STALE;
    }
}
```

```php
use SineMacula\Laravel\Sso\Contracts\Freshness;

public function register(): void
{
    $this->app->singleton(Freshness::class, RecentSignInFreshness::class);
}
```

One bound in a provider that registers before the package's is kept; one bound later replaces the default as any later
binding does. The package resolves the contract on every question, so a contract bound with `scoped()` is rebuilt for
each request. Whichever you choose, under Octane or a queue worker it must read the caller afresh on each call and keep
nothing of one request or job for the next, as the example does by resolving the request each time. A timestamp in the
future, or one your application cannot vouch for, is `stale`. If you key a stricter policy on the operation (asking
for a second factor before `sso.connection.trust`, say), match on its stable name, never on its position.

## The order every change follows

Each change finds what it changes, validates what it was given, asks the contract, and only then writes, in one
transaction, reporting the change inside it. So a refusal never leaves a partial change or an event behind, and asking
for fresh authentication inside a transaction your application opened is safe: nothing is written before the answer.

## Testing with `FakeFreshness`

`SineMacula\Laravel\Sso\Testing\FakeFreshness` answers what your test tells it and records every question with its
maximum age. Bind it in place of the contract, run the change, then assert what was asked:

```php
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;

$freshness = FakeFreshness::fresh()->staleFor(FreshnessOperation::CONNECTION_DELETE);

$this->app->instance(Freshness::class, $freshness);

// ... enable a connection, then try to delete it

$freshness->assertAsked(FreshnessOperation::CONNECTION_ENABLE, 300);
$freshness->assertAskedExactly([FreshnessOperation::CONNECTION_ENABLE, FreshnessOperation::CONNECTION_DELETE]);
```

| Method                                                                   | What it does                                                                                    |
|--------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| `new FakeFreshness(FreshnessOutcome $outcome = FreshnessOutcome::FRESH)` | Answers the outcome given for every operation                                                   |
| `FakeFreshness::fresh()`, `FakeFreshness::stale()`                       | Answers `fresh`, or `stale`, for every operation                                                |
| `staleFor(FreshnessOperation ...$operations)`                            | Answers `stale` for the operations given and `fresh` for every other; a later call adds to them |
| `asked()`                                                                | Every question, in order, as `['operation' => ..., 'max_age_seconds' => ...]`                   |
| `assertAsked(FreshnessOperation $operation, ?int $maxAgeSeconds = null)` | Fails unless the operation was asked about, with the maximum age when one is given              |
| `assertAskedExactly(array $operations)`                                  | Fails unless exactly those operations were asked about, in that order                           |
| `assertNotAsked(?FreshnessOperation $operation = null)`                  | Fails if the operation was asked about or, with none given, if anything was                     |

Each fake holds its own answers and questions, so bind a new one in each test. It judges no caller: never bind it
outside your tests.
