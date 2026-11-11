# Clock

## Purpose

This note records how the package tells the time: the one clock every time check reads, the clock skew those checks
allow, and the frozen clock a test binds in its place, so skew, expiry and maximum ages can be tested without waiting
(SSO-11.13, SSO-6.5).

## Invariants

- There is one clock: `Contracts\Clock`, PSR-20 shaped (it extends `Psr\Clock\ClockInterface`), whose `now()` answers a
  `Carbon\CarbonImmutable`. Every time check of the package (SAML `NotBefore`, `NotOnOrAfter` and `IssueInstant`, OIDC
  `exp`, `iat` and `auth_time`, and every stored expiry: single-use keys, authorisation requests, handoff codes, rate
  limit windows, pending claims) reads it from the container. Nothing in the package calls `Carbon::now()`,
  `CarbonImmutable::now()`, `Date::now()`, `now()`, `time()` or `new \DateTime` for a time check.
- The default, `Clock\SystemClock`, answers `CarbonImmutable::instance(Date::now())` on every call. It follows
  Laravel's test clock (`Carbon::setTestNow()`, `Date::setTestNow()`, `travelTo()`, `freezeTime()`), so freezing
  Laravel's clock freezes the package's. It is a `CarbonImmutable` itself whatever class the application's date factory
  makes (`Date::use()` with Laravel's `Carbon`, `Carbon`, `CarbonImmutable`, PHP's `DateTime` or `DateTimeImmutable`, or
  a callable), to the microsecond.
- `SystemClock` holds nothing, so the provider binds it as a singleton default: one instance serves every request and
  job of an Octane or queue worker, and no instant outlives the call that read it (SSO-11.2). A clock the application
  or another package bound before the provider registers is kept; one bound afterwards replaces it, as any later
  binding does.
- The clock skew is `Clock\ClockSkew::seconds()`, read from `sso.clock.skew_seconds` on each call: an integer from 0 to
  300 (`ClockSkew::MAX_SECONDS`, five minutes), or the digit string `env()` gives for one, defaulting to 60
  (`ClockSkew::DEFAULT_SECONDS`) when unset (SSO-6.5). It is read through `Config\IntegerSetting`, so the boot check and
  the time checks judge it the same way.
- A malformed skew fails closed: `ClockSkew::seconds()` throws an `InvalidArgumentException` with
  `sso.clock.skew_seconds must be an integer from 0 to 300.`, naming the key and the range, never the value. It never
  falls back to the default or clamps to the range, either of which would silently widen or narrow the window.
- `[clock]` (`Clock\ClockCheck`) applies while the package is in use (`Config\Features::isInUse()`) and reads the skew
  as `ClockSkew::seconds()` does, so a malformed skew stops the boot and is reported by `sso:check`.
- `Testing\FrozenClock` is a public test double (`@api`): it holds one `CarbonImmutable` (the instant given as a string
  or any `DateTimeInterface`, or the instant it was built at) until `advance()` (backwards when negative) or `setTo()`
  moves it. It copies a mutable date it is given, and once built it does not follow Laravel's test clock.

## Success Path

1. The provider binds `Contracts\Clock` to `SystemClock` as a singleton default, unless the application bound a clock
   first.
2. A time check resolves the clock, reads `now()` once for the decision, and compares it with the protocol's instants,
   allowing `ClockSkew::seconds()` either side where the protocol allows a skew.
3. A test freezes Laravel's clock (`travelTo()`, `Carbon::setTestNow()`) and the package's checks see the frozen
   instant, or it binds `new FrozenClock(...)` with `$app->instance(Clock::class, ...)` and moves it with `advance()`
   and `setTo()` to cross an expiry or a skew boundary.

## Failure / Edge Cases

- An application's date factory that makes a mutable or non-Carbon class still yields a `CarbonImmutable`, so a caller
  that adds to the instant never changes another's.
- A skew of `-1`, `301`, `'1.5'`, `1.5`, `null`, `''`, a padded or signed string, a boolean or an array is refused with
  the one message; `0` (no skew) and `300` are accepted.
- An unset skew (a configuration published before the setting existed) is 60 seconds.
- `[clock]` is not run while neither protocol is on, however malformed the skew; a malformed protocol switch counts as
  on, so the skew is checked rather than skipped.
- A string `FrozenClock` cannot parse throws Carbon's `InvalidFormatException`, an `InvalidArgumentException`.
- A clock bound in place of `SystemClock` must hold no request state of its own beyond what a test sets, since it is
  resolved once per worker.

## Implementation Anchors

- `src/Contracts/Clock.php`.
- `src/Clock/SystemClock.php`, `src/Clock/ClockSkew.php`, `src/Clock/ClockCheck.php`.
- `src/Testing/FrozenClock.php`.
- `src/SsoServiceProvider.php`: `register()` (the singleton default `Support\PackageDefaults` lists) and
  `CONFIGURATION_CHECKS['clock']`; `config/sso.php`: `clock.skew_seconds`.

## Authoritative Tests

- `tests/Unit/Clock/SystemClockTest.php`.
- `tests/Unit/Testing/FrozenClockTest.php`.
- `tests/Feature/Clock/ClockSkewTest.php`, `tests/Feature/Clock/ClockCheckTest.php`,
  `tests/Feature/Clock/ClockBindingTest.php`.
- `tests/Integration/Clock/ClockAcrossRequestsTest.php`.
- `tests/Unit/SsoServiceProviderTest.php` `testEachDefaultIsSharedAsItsStateAllows`,
  `testEachContractIsBoundToItsDefault`, `testABindingMadeBeforeIsKept`.

## Change Triggers

- A new time check, or a time check that reads anything but `Contracts\Clock` and `ClockSkew::seconds()`.
- A change to the skew's default, ceiling, key or message, or to when `[clock]` applies.
- A change to the `Clock` contract, to how `SystemClock` reads Laravel's clock, or to how it is bound.
- A change to what `FrozenClock` accepts or how it moves.
