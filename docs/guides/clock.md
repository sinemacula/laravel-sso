# Clock

Every time check the package makes (a SAML assertion's `NotBefore` and `NotOnOrAfter`, an OIDC token's `exp`, `iat` and
`auth_time`, and the expiry of everything it stores) reads one clock, `SineMacula\Laravel\Sso\Contracts\Clock`. Its
`now()` answers a `Carbon\CarbonImmutable`, and it is a PSR-20 `ClockInterface`, so you can pass it anywhere one is
expected.

## Clock skew

Identity providers' clocks drift from yours, so the protocol time checks allow a skew either side:

| Key                  | Default | Env                      |
|----------------------|---------|--------------------------|
| `clock.skew_seconds` | `60`    | `SSO_CLOCK_SKEW_SECONDS` |

The skew is a whole number of seconds from `0` (none) to `300` (five minutes). Anything else (a negative number, more
than `300`, a fraction, an empty value) fails closed when a time check reads it, and stops the boot outside the console,
with `sso.clock.skew_seconds must be an integer from 0 to 300.`; `php artisan sso:check` reports it under `[clock]`.
Raise the skew only as far as the drift you see from your identity providers: every second you add lets an expired
assertion or token through for a second longer.

Your own code can read the same value with `SineMacula\Laravel\Sso\Clock\ClockSkew::seconds()`.

## The default clock

The package binds `Clock\SystemClock`, which reads Laravel's `Date` facade on every call. It follows Laravel's test
clock, so anything that freezes or moves Laravel's time (`freezeTime()`, `freezeSecond()`, `travelTo()`,
`Carbon::setTestNow()`) moves the package's too. In a test frozen to the second, ten minutes of time travel takes an
authorisation request to the end of its lifetime (`authorization_requests.ttl_seconds`, `600` by default), and the
provider's response is refused; `startFlow()` and `respondAtProvider()` are the steps of the examples' test case in
[Testing Your SSO Flows](testing.md):

<!-- snippet: tests/Integration/Examples/Clock/ClockExampleTest.php#default-clock -->
```php
$start = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

$this->travelTo(now()->addMinutes(10));

$redirect = $this->respondAtProvider($provider, $connectionId, $start);

self::assertSame(FailureReason::REQUEST_EXPIRED->value, $redirect->error);
```

It holds nothing between calls, so it is shared by every request and job a long-lived worker (Octane, `queue:work`)
serves.

## Binding your own clock

Bind your own implementation of `Contracts\Clock` in a service provider's `register()`. One bound in a provider that
registers before the package's is kept; one bound later, as your application's providers are, replaces the default as
any later binding does. Either way, it must answer a `CarbonImmutable` and must not hold an instant from one request or
job to the next. Here `UtcClock` answers Laravel's current instant in UTC, read afresh on every call:

<!-- snippet: tests/Integration/Examples/Clock/AppServiceProvider.php#own-clock -->
```php
// One clock for every request and job: it holds no instant between them
$this->app->singleton(Clock::class, UtcClock::class);
```

## A frozen clock in tests

`SineMacula\Laravel\Sso\Testing\FrozenClock` holds one instant until your test moves it, so a test of an expiry or the
skew neither waits nor depends on when it runs. Bind it in place of the package's clock, and move it forwards, backwards
or to a given instant:

<!-- snippet: tests/Integration/Examples/Clock/ClockExampleTest.php#frozen-clock-bound -->
```php
$clock = new FrozenClock('2026-10-31T12:00:00Z');

$this->instance(Clock::class, $clock);

$clock->advance(61);

self::assertSame('2026-10-31T12:01:01Z', app(Clock::class)->now()->toIso8601ZuluString());

$clock->advance(-120);

self::assertSame('2026-10-31T11:59:01Z', app(Clock::class)->now()->toIso8601ZuluString());

$clock->setTo('2026-11-01T00:00:00Z');

self::assertSame('2026-11-01T00:00:00Z', app(Clock::class)->now()->toIso8601ZuluString());
```

| Method                                                         | What it does                                                         |
|----------------------------------------------------------------|----------------------------------------------------------------------|
| `new FrozenClock(DateTimeInterface\|string\|null $now = null)` | Holds the instant given, or the instant it was built at when none is |
| `now()`                                                        | The instant it holds, as a `CarbonImmutable`                         |
| `advance(int $seconds)`                                        | Moves it by the seconds given, backwards when negative               |
| `setTo(DateTimeInterface\|string $instant)`                    | Moves it to the instant given                                        |

An instant is a string `CarbonImmutable::parse()` reads, or any `DateTimeInterface` (a mutable `DateTime` is copied, so
changing it later does not move the clock); a string Carbon cannot parse throws an `InvalidArgumentException`. Once
built, a `FrozenClock` does not follow `travelTo()` or `Carbon::setTestNow()`: freeze Laravel's clock instead when you
want the two to move together.
