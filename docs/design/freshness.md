# Freshness

## Purpose

This note records how the package asks for fresh authentication before each operation that could widen or redirect
access, or destroy it: the contract it asks, the stable operation names it asks with, the maximum age configured for
each, the default that refuses, and the gate every listed mutation calls before it writes (SSO-2.12).

## Invariants

- There is one contract: `Contracts\Freshness::check(FreshnessOperation $operation, int $maxAgeSeconds)`, answering a
  `Freshness\Enums\FreshnessOutcome`, `fresh` or `stale` (`isFresh()` is true for `fresh` alone). It answers `fresh`
  only when the caller of the request or job being served authenticated no more than `$maxAgeSeconds` ago, and `stale`
  otherwise, including when there is no caller it can judge (a queued job, a console command). An error it cannot
  answer through propagates as a server error; it never answers `fresh` when it cannot tell.
- The operations are `Freshness\Enums\FreshnessOperation`, eleven cases whose values are the stable names SSO-2.12
  lists, in this order: `sso.connection.trust`, `sso.connection.enable`, `sso.connection.delete`,
  `sso.connection.idp_initiated`, `sso.keys.rotate`, `sso.domain.claim`, `sso.domain.verify`, `sso.domain.remove`,
  `sso.enforcement.update`, `sso.link.create` and `sso.link.remove`. A name is stable once released: it is never
  renamed or reused, since an adapter (`laravel-iam`'s among them) may key its own policy on it.
- Each operation has its own maximum age, read by `Freshness\MaximumAges::for()` from
  `sso.freshness.max_age_seconds.<key>` on each call, where the key is `FreshnessOperation::configKey()`: the name after
  `sso.`, with the dots as underscores (`sso.connection.trust` is `connection_trust`). Each defaults to 300 seconds
  (`MaximumAges::DEFAULT_SECONDS`) when unset, and is shipped at 300, a production-safe five minutes.
- An age is an integer from 1 (`MaximumAges::MIN_SECONDS`) to 3600 (`MaximumAges::MAX_SECONDS`, an hour), or the digit
  string `env()` gives for one, read through `Config\IntegerSetting`. Anything else fails closed with an
  `InvalidArgumentException`, `sso.freshness.max_age_seconds.<key> must be an integer from 1 to 3600.`, naming the key
  and never the value. It never falls back to the default or clamps to the range, either of which would loosen the
  requirement the setting was meant to set.
- The default, `Freshness\RefusingFreshness`, answers `stale` for every operation at every age. It holds nothing, so
  the provider binds it with `singletonIf`: an application or another package that bound the contract before the
  provider registers keeps its binding, and one bound afterwards replaces the default.
- Every operation SSO-2.12 lists asks through `Freshness\FreshnessGate`, never the contract directly.
  `FreshnessGate::check()` reads the operation's maximum age first, then resolves the contract from the container and
  asks it with the operation and that age. `checkAll()` asks about each operation of a change that is several at once
  (a trust change that also turns IdP-initiated sign-in on, say) once each, in the order given, and answers `stale` at
  the first that is, asking about none after it; with no operation it answers `fresh` and asks nothing.
- The contract is resolved on each call and the age read on each call, so a binding made per request or swapped in a
  test is the one asked, and nothing of one caller is kept for the next (SSO-11.2). An implementation the application
  binds reads its caller from the request or job being served on each call and keeps nothing of one for the next.
- Every mutation follows one order: find what it changes on the write connection; validate what it was given; ask the
  gate with each operation the change is; then write, in one transaction on the storage connection, reporting through
  `Administration\AdministrationEvents` inside it. A change's operations come from the settings it touches
  (`Contracts\ProtocolSettings::freshnessFor()`) and from what a key row is for (`Keys\Enums\KeyUse::freshness()`).
- A refusal writes nothing and reports nothing: a `stale` answer ends the helper with a result whose reason is
  `FailureReason::FRESHNESS_REQUIRED` (`freshness_required`), so the application can ask the caller to authenticate
  again and retry. No row changes, no event is dispatched, and no failure event is reported for it.
- The gate may be asked inside a transaction the application opened, since it reads configuration and calls the
  contract only; but nothing is written before the answer, so a refusal has nothing to roll back.
- `[freshness]` (`Freshness\FreshnessCheck`) applies while the package is in use (`Config\Features::isInUse()`): the
  block must be an array (else `` `sso.freshness.max_age_seconds` must be an array of maximum ages by operation. ``),
  with no key that names no operation (else one problem naming every such key and listing the operations, since a
  misspelt key would leave the operation meant at its default), and each age is read as `MaximumAges::for()` reads it,
  one problem per malformed age in the order of the operations.
- `Testing\FakeFreshness` is a public test double (`@api`): it answers `fresh` unless built `stale()` or told with
  `staleFor()` which operations alone answer `stale`, records every question with its maximum age, and asserts what
  was asked. It holds its state per instance and never belongs in production.

## Success Path

1. The provider binds `Contracts\Freshness` to `RefusingFreshness` with `singletonIf`, unless the application bound a
   contract first; `laravel-iam` binds `laravel-authentication`'s freshness check (AUTH-3.11), passing the maximum age
   on as the caller's requirement.
2. A management helper finds the connection (and the key) on the write connection, and validates what it was given.
3. It asks `FreshnessGate::check()` with the one operation the change is, or `checkAll()` with each; the gate reads
   each maximum age from `sso.freshness.max_age_seconds`, resolves the bound contract and asks it.
4. On `fresh`, the helper writes in one transaction on the storage connection and reports the change inside it; the
   event is dispatched once the transaction commits.

## Failure / Edge Cases

- With the default binding, every listed operation answers `freshness_required`; the package does not work around it.
- A malformed maximum age throws before the contract is asked, so the misconfigured operation is never let through on
  the contract's answer; `[freshness]` reports it at boot and in `sso:check`, and the other operations still read
  theirs.
- An age of `0`, `3601`, a negative number, a float (`300.0` included), a decimal, signed, padded or spaced string, an
  exponent, a word, `''`, `null`, a boolean or an array is refused with the one message; `1`, `3600` and a digit string
  such as `'600'` are accepted.
- An unset age, an empty block or a missing `freshness` section reads 300 for every operation; a block that is not an
  array is reported once by `[freshness]`, and every operation then reads its default.
- An operation listed twice in `checkAll()` is asked about once; a malformed age partway through `checkAll()` throws
  after the operations before it were asked and before it or any after is.
- `[freshness]` is not run while neither protocol is on, however malformed the block; a malformed protocol switch
  counts as on, so the block is checked rather than skipped.
- A contract that throws propagates as a server error; it is never read as `fresh` or `stale`.
- Under Octane or a queue worker the default is shared by every request and job, which it can be because it holds
  nothing; a contract bound in its place must hold no caller from one request or job to the next, and since the gate
  resolves it on each call, a contract bound per request (`scoped`) is the one each request asks.

## Implementation Anchors

- `src/Contracts/Freshness.php`.
- `src/Freshness/Enums/FreshnessOperation.php`, `src/Freshness/Enums/FreshnessOutcome.php`.
- `src/Freshness/RefusingFreshness.php`, `src/Freshness/MaximumAges.php`, `src/Freshness/FreshnessGate.php`,
  `src/Freshness/FreshnessCheck.php`.
- `src/Testing/FakeFreshness.php`.
- `src/SsoServiceProvider.php`: `register()` (`singletonIf(Freshness::class, RefusingFreshness::class)`) and
  `CONFIGURATION_CHECKS['freshness']`; `config/sso.php`: `freshness.max_age_seconds`.
- `src/Events/Enums/FailureReason.php`: `FRESHNESS_REQUIRED`; `src/Contracts/ProtocolSettings.php`: `freshnessFor()`;
  `src/Keys/Enums/KeyUse.php`: `freshness()`.

## Authoritative Tests

- `tests/Unit/Freshness/Enums/FreshnessOperationTest.php` `testTheOperationsAreTheStableNames`,
  `testEachOperationHasItsNameAndKey`, `testEveryKeyIsDistinctAndOneSegment`,
  `testTheShippedBlockHasEveryKeyAndNoOther`.
- `tests/Unit/Freshness/Enums/FreshnessOutcomeTest.php` `testTheOutcomesAreFreshAndStale`, `testOnlyFreshIsFresh`.
- `tests/Unit/Freshness/RefusingFreshnessTest.php` `testRefusesTheOperationAtEveryAge`.
- `tests/Unit/Testing/FakeFreshnessTest.php`.
- `tests/Feature/Freshness/MaximumAgesTest.php` `testAnUnsetAgeIsTheDefault`, `testEachOperationReadsItsOwnKey`,
  `testReadsTheAgeOnEachCall`, `testAcceptsEachAge`, `testRefusesEachMalformedAge`.
- `tests/Feature/Freshness/FreshnessGateTest.php` `testAsksTheBoundContractWithTheConfiguredAge`,
  `testResolvesTheContractOnEachCall`, `testAMalformedAgeThrowsBeforeTheContractIsAsked`,
  `testCheckAllAsksInTheOrderGiven`, `testCheckAllAsksAboutEachOperationOnce`, `testCheckAllStopsAtTheFirstStale`,
  `testCheckAllOfNoOperationIsFresh`, `testCheckAllThrowsAtAMalformedAge`.
- `tests/Feature/Freshness/FreshnessCheckTest.php` `testAppliesOnlyWhileThePackageIsInUse`,
  `testReportsABlockThatIsNotAnArray`, `testReportsAnUnknownOperation`, `testReportsEachAgeOutOfRange`,
  `testReportsTheShapeBeforeTheAges`.
- `tests/Feature/Freshness/FreshnessBindingTest.php` `testTheRefusingContractIsTheDefault`,
  `testTheDefaultIsASingleton`, `testAContractBoundBeforeTheProviderRegistersIsKept`,
  `testAContractBoundAfterwardsReplacesTheDefault`.
- `tests/Integration/Freshness/DefaultFreshnessRefusesTest.php` `testTheDefaultRefusesEveryOperation`,
  `testAFreshContractLetsEveryOperationThrough`, `testEachRequestAsksTheContractBoundWhenItIsServed`.
- `tests/Unit/SsoServiceProviderTest.php` `testEachDefaultIsSharedAsItsStateAllows`.
- Each management helper's own test that a stale caller is refused, writing and reporting nothing (the convention every
  item that adds a listed mutation follows).

## Change Triggers

- A new operation that could widen, redirect or destroy access, a renamed or removed operation name, or a change to how
  `configKey()` derives a key.
- A change to an age's default, bounds, key or message, or to when `[freshness]` applies or what it reports.
- A mutation that writes before asking the gate, asks the contract directly, or reports on a refusal.
- A change to the `Freshness` contract or its outcomes, to the default or how it is bound, or to whether the gate
  resolves the contract on each call.
- A change to what `FakeFreshness` answers, records or asserts.
