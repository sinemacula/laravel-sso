# Freshness

## Purpose

This note records how the package asks for fresh authentication before each operation that could widen or redirect
access, or destroy it: the contract it asks, the stable operation names it asks with, the maximum age configured for
each, the default that refuses, and the gate every listed mutation calls before it writes (SSO-2.12).

## Invariants

- There is one contract: `Contracts\Freshness::check(FreshnessOperation $operation, int $maxAgeSeconds, ?Caller
  $caller)`, answering a `Freshness\Enums\FreshnessOutcome`, `fresh` or `stale` (`isFresh()` is true for `fresh`
  alone). The caller is the one the action is taken for, as the application gave it (`Identities\Caller`: the identity
  and, when supplied, the session it is on); the implementation judges that caller and its session, never the request
  or job being served. It answers `fresh` only when that caller authenticated no more than `$maxAgeSeconds` ago, and
  `stale` otherwise, including for no caller (a scheduled job, a console command) and for a caller it cannot judge
  (one with no session when it judges sessions). An error it cannot answer through propagates as a server error; it
  never answers `fresh` when it cannot tell.
- A caller (`Identities\Caller`, `@api`) is an `IdentityReference` and an optional session id of 1 to 255 bytes
  (`Caller::MAX_SESSION_ID_LENGTH`); an empty or longer one is an `InvalidArgumentException`. `null` where a caller is
  taken means no authenticated person, and a caller with no session means none was supplied, never "the current
  session": the package reads no request, job or session to find one.
- The operations are `Freshness\Enums\FreshnessOperation`, twelve cases whose values are the stable names of the
  operations SSO-2.12 lists, in this order: `sso.connection.trust`, `sso.connection.enable`,
  `sso.connection.disable`, `sso.connection.delete`, `sso.connection.idp_initiated`, `sso.keys.rotate`,
  `sso.domain.claim`, `sso.domain.verify`, `sso.domain.remove`, `sso.enforcement.update`, `sso.link.create` and
  `sso.link.remove`. Enabling and disabling a connection are separate operations, each with its own name and maximum
  age, so a policy can treat restoring access differently from removing it. A name is stable once released: it is
  never renamed or reused, since an adapter (`laravel-iam`'s among them) may key its own policy on it.
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
  the provider binds it as a singleton default: an application or another package that bound the contract before the
  provider registers keeps its binding, and one bound afterwards replaces the default.
- Every operation SSO-2.12 lists asks through `Freshness\FreshnessGate`, never the contract directly.
  `FreshnessGate::check()` reads the operation's maximum age first, then resolves the contract from the container and
  asks it with the operation, that age and the caller it was given. `checkAll()` asks about each operation of a change
  that is several at once (a trust change that also turns IdP-initiated sign-in on, say) once each, in the order given,
  and answers `stale` at the first that is, asking about none after it, each for the one caller given; with no operation
  it answers `fresh` and asks nothing.
- The contract is resolved on each call and the age read on each call, so a binding made per request or swapped in a
  test is the one asked, and nothing of one caller is kept for the next (SSO-11.2). An implementation the application
  binds judges the caller each call is given and keeps nothing of one for the next.
- Every action that asks takes its caller as a plain value (`?Caller $caller`, after the client) and gives that same
  caller to the gate; an administration change's event names the caller's identity as the acting identity and never
  carries its session. A `link` start gives its caller, with the session it gave, to freshness and binds the identity
  alone; a `link` redemption gives the caller it was made for. Scheduled and console work passes no caller: a metadata
  refresh the schedule or the queue makes asks no freshness at all, and an administrator's `refreshNow()` requires its
  caller.
- Every mutation follows one order: find what it changes on the write connection and validate what it was given; then,
  in one transaction on the storage connection, take its locks, judge again what they hold, ask the gate with each
  operation the change is, and write, reporting through `Administration\AdministrationEvents` inside it. So the
  contract is asked after every lock the package takes for the change, and an implementation may lock the caller's
  session row there, last, with a current read. A change's operations come from the settings it touches
  (`Contracts\ProtocolSettings::freshnessFor()`) and from what a key row is for (`Keys\Enums\KeyUse::freshness()`).
- Three changes do outward or costly work before their transaction, and ask the gate before it too, so a stale caller
  spends nothing: `DomainService::verify()` before its rate limited DNS lookup, `KeyService::addNext()` before it
  generates a key pair, and `MetadataRefresher::refreshNow()` before its claim and fetch. The answer under the locks
  decides; the first only spares the work. A metadata refresh asks under `Metadata\RefreshWriter::locked()`'s lock, and
  a caller found stale there releases the claim and writes nothing else.
- A link start asks before it stores its request, in no transaction, and the redemption asks again under its own
  locks (`Handoffs\Redemption\LinkBranch`).
- A refusal writes nothing and reports nothing: a `stale` answer ends the helper with a result whose reason is
  `FailureReason::FRESHNESS_REQUIRED` (`freshness_required`), so the application can ask the caller to authenticate
  again and retry. No row changes, no event is dispatched, and no failure event is reported for it. The one row a
  refusal can leave is the unconfigured guard row an enforcement change locks, which stores no rule (`enforcement.md`).
- The gate is asked inside the package's transaction, a savepoint of one the application opened, and the contract may
  be asked again when that transaction is retried after a deadlock. An implementation keeps nothing of one answer for
  the next.
- `[freshness]` (`Freshness\FreshnessCheck`) applies while the package is in use (`Config\Features::isInUse()`): the
  block must be an array (else `` `sso.freshness.max_age_seconds` must be an array of maximum ages by operation. ``),
  with no key that names no operation (else one problem naming every such key and listing the operations, since a
  misspelt key would leave the operation meant at its default), and each age is read as `MaximumAges::for()` reads it,
  one problem per malformed age in the order of the operations.
- `Testing\FakeFreshness` is a public test double (`@api`): it answers `fresh` unless built `stale()` or told with
  `staleFor()` which operations alone answer `stale`, records every question with its maximum age and caller, and
  asserts what was asked. It holds its state per instance and never belongs in production.

## Success Path

1. The provider binds `Contracts\Freshness` to `RefusingFreshness` as a singleton default, unless the application bound
   a contract first; `laravel-iam` binds `laravel-authentication`'s freshness check (AUTH-3.11), passing the maximum age
   on as the caller's requirement.
2. A management helper finds the connection (and the key) on the write connection, and validates what it was given.
3. It asks `FreshnessGate::check()` with the one operation the change is, or `checkAll()` with each, for the caller it
   was given; the gate reads each maximum age from `sso.freshness.max_age_seconds`, resolves the bound contract and
   asks it with that caller.
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

- `src/Contracts/Freshness.php`, `src/Identities/Caller.php`.
- `src/Freshness/Enums/FreshnessOperation.php`, `src/Freshness/Enums/FreshnessOutcome.php`.
- `src/Freshness/RefusingFreshness.php`, `src/Freshness/MaximumAges.php`, `src/Freshness/FreshnessGate.php`,
  `src/Freshness/FreshnessCheck.php`.
- `src/Testing/FakeFreshness.php`.
- `src/SsoServiceProvider.php`: `register()` (the singleton default `Support\PackageDefaults` lists) and
  `CONFIGURATION_CHECKS['freshness']`; `config/sso.php`: `freshness.max_age_seconds`.
- `src/Events/Enums/FailureReason.php`: `FRESHNESS_REQUIRED`; `src/Contracts/ProtocolSettings.php`: `freshnessFor()`;
  `src/Keys/Enums/KeyUse.php`: `freshness()`.

## Authoritative Tests

- `tests/Unit/Freshness/Enums/FreshnessOperationTest.php` `testTheOperationsAreTheStableNames`,
  `testEachOperationHasItsNameAndKey`, `testEveryKeyIsDistinctAndOneSegment`,
  `testTheShippedBlockHasEveryKeyAndNoOther`.
- `tests/Unit/Freshness/Enums/FreshnessOutcomeTest.php` `testTheOutcomesAreFreshAndStale`, `testOnlyFreshIsFresh`.
- `tests/Unit/Freshness/RefusingFreshnessTest.php` `testRefusesTheOperationAtEveryAge`.
- `tests/Unit/Identities/CallerTest.php` `testKeepsTheIdentityAndTheSessionGiven`, `testRefusesAMalformedSessionId`.
- `tests/Unit/Testing/FakeFreshnessTest.php`.
- `tests/Feature/Freshness/MaximumAgesTest.php` `testAnUnsetAgeIsTheDefault`, `testEachOperationReadsItsOwnKey`,
  `testReadsTheAgeOnEachCall`, `testAcceptsEachAge`, `testRefusesEachMalformedAge`.
- `tests/Feature/Freshness/FreshnessGateTest.php` `testAsksTheBoundContractWithTheConfiguredAge`,
  `testResolvesTheContractOnEachCall`, `testAMalformedAgeThrowsBeforeTheContractIsAsked`,
  `testCheckAllAsksInTheOrderGiven`, `testCheckAllAsksEachOperationForTheCaller`,
  `testCheckAllAsksAboutEachOperationOnce`, `testCheckAllStopsAtTheFirstStale`, `testCheckAllOfNoOperationIsFresh`,
  `testCheckAllThrowsAtAMalformedAge`.
- `tests/Feature/Administration/FreshnessConventionTest.php` `testAFreshCallerIsAskedExactlyItsOperations`,
  `testTheCallerAskedAboutIsTheOneTheEventNames`.
- `tests/Feature/Freshness/FreshnessCheckTest.php` `testAppliesOnlyWhileThePackageIsInUse`,
  `testReportsABlockThatIsNotAnArray`, `testReportsAnUnknownOperation`, `testReportsEachAgeOutOfRange`,
  `testReportsTheShapeBeforeTheAges`.
- `tests/Feature/Freshness/FreshnessBindingTest.php` `testTheRefusingContractIsTheDefault`,
  `testTheDefaultIsASingleton`, `testAContractBoundBeforeTheProviderRegistersIsKept`,
  `testAContractBoundAfterwardsReplacesTheDefault`.
- `tests/Integration/Freshness/DefaultFreshnessRefusesTest.php` `testTheDefaultRefusesEveryOperation`,
  `testAFreshContractLetsEveryOperationThrough`, `testEachRequestAsksTheContractBoundWhenItIsServed`.
- `tests/Unit/SsoServiceProviderTest.php` `testEachDefaultIsSharedUnderItsKeyAndNeverByTheContract`.
- Each management helper's own test that a stale caller is refused, writing and reporting nothing.

## Change Triggers

- A new operation that could widen, redirect or destroy access, a renamed or removed operation name, or a change to how
  `configKey()` derives a key.
- A change to an age's default, bounds, key or message, or to when `[freshness]` applies or what it reports.
- A mutation that writes before asking the gate, asks the contract directly, or reports on a refusal.
- A change to the `Freshness` contract, its caller or its outcomes, to the default or how it is bound, or to whether the
  gate resolves the contract on each call.
- A change to what `FakeFreshness` answers, records or asserts.
