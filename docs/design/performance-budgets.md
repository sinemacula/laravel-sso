# Performance Budgets

## Purpose

This note records what the package's operations cost and how that is held still: deterministic query budgets, enforced
in CI on every engine, and PHPBench benches, run only when scheduled or asked for, which time validation and address
classification and gate nothing.

## Invariants

### Budgets

- A budget pins the exact reads and writes of a call through `PerformanceContractTestCase::assertQueryBudget()`. It is
  never a time. Each statement sent must be data manipulation, so a statement that changes the schema fails it.
- A budget found wrong is a defect to report, not a number to change: the statement behind it is either a cost the note
  of that operation owes an explanation for, or a regression.
- `useSeparateCounters()` moves the counters to a connection of their own, on the same engine as the storage connection,
  and records that connection apart. The budget's last two arguments are then its reads and writes, and
  `statementsSent()` and `counterStatementsSent()` say which statement went where.
- The budgets hold on SQLite, PostgreSQL and MySQL alike, run one engine at a time through `phpunit`.

### What each operation is budgeted by

- Start: `AuthorizationRequestQueryBudgetTest`.
- Completion over a scripted driver: `CompletionQueryBudgetTest`.
- Real SAML completion and encrypted assertions: `SamlCompletionQueryBudgetTest`.
- OIDC callbacks by client secret and client assertion, with doubles of validation and claims:
  `OidcCallbackQueryBudgetTest`.
- Discovery, match and miss: `DiscoveryQueryBudgetTest`.
- Enforcement: `EnforcementQueryBudgetTest`, and the cases under enforcement in the completion's and the handoff's.
- Reservation and activation: `LinkingQueryBudgetTest`.
- Provisioning: `ProvisioningQueryBudgetTest`.
- Sign-in and link redemption: `HandoffQueryBudgetTest`.
- Reauthentication redemption: `ReauthenticationQueryBudgetTest`.
- Recheck, refresh and JWKS: `DomainRecheckQueryBudgetTest`, `MetadataRefreshQueryBudgetTest`,
  `OidcRefreshQueryBudgetTest`.
- Whole flows, on both connections: `FullFlowQueryBudgetTest`.
- Pruning, on both connections: `OperationsQueryBudgetTest`.
- The expiry report: `ExpiryReportQueryBudgetTest`.
- Growth across many rows and connections: `QueryGrowthTest`.

### Whole flows

`FullFlowQueryBudgetTest` combines what the budgets above leave apart: the real drivers and validators against the fake
providers, the package's own handoff store and link store, a tenant's rule on and satisfied, and the counters apart.
Each is measured once its counters exist. Reads and writes are the storage connection's, with the counters' writes in
brackets; none of them reads a counter.

| Flow                                 | Start        | Completion    | First redemption |
|--------------------------------------|--------------|---------------|------------------|
| OIDC, client secret                  | 2, 2 (1)     | 8, 7 (2)      | 6, 5 (1)         |
| OIDC, `private_key_jwt`              | 3, 2 (1)     | 12, 7 (2)     | 7, 5 (1)         |
| SAML, signed, email mapped           | 3, 2 (1)     | 11, 8 (2)     | 7, 5 (1)         |
| SAML, encrypted required             | 4, 2 (1)     | 15, 8 (2)     | 8, 5 (1)         |
| Discovery, then OIDC, email mapped   | 3, 2 (2)     | 9, 7 (2)      | not measured     |

A later redemption of a connection writes one less, since the first sign-in's mark is already on it.

### Growth

A small fixed fixture cannot reveal an N+1. `QueryGrowthTest` therefore measures each operation at N and at 3N, each
budget being its fixed cost plus its cost per unit times the units, so the difference is exactly that cost:

- The expiry report costs nothing per key already notified, and 2 reads and 3 writes per key warned of, beside 2 reads
  per page and 1 for the empty page after a full one.
- The due-connection listing costs nothing per connection, beside 2 reads per chunk (the chunk and its anchors) and 1
  for the empty chunk after a full one.
- The domain recheck costs 3 reads and 2 writes per claim, beside 1 read per chunk and 1 for the empty chunk after a
  full one.
- Pruning reservations costs 1 read and 2 writes per connection in a batch and nothing per reservation, beside 1 read
  per page and 1 for the empty page after a full one.

### Benches

- `benchmarks/` isolates what a budget cannot show: `SamlValidationBench`, `IdTokenValidationBench` and
  `AddressPolicyBench`, each over valid and rejected inputs, beside `ServiceProviderBench`.
- A bench's fixtures are built once in `#[BeforeMethods]`, so no subject times key generation, signing, DNS or HTTP. A
  validator's own reads of the connection and its keys are part of what it costs, on the in-memory SQLite database of
  `Benchmarks\Support\BenchApplication`, which is the only code the benches share.
- The benches stay scheduled and manual (`composer bench:ci`, the `benchmarks` job of `quality-gates.yml`). There is no
  time threshold anywhere in CI, and no bench carries `#[Assert]`.
- A broken bench stays visible: `BenchmarksRunTest` runs every subject once under PHPUnit, through its prepared
  fixtures, and asserts that each completes, that a valid input validates and that a rejected one is rejected for its
  reason.

### Where the environment and the versions appear

`bench:ci` dumps the report to `build/phpbench.xml`, uploaded as the job's `phpbench-report` artefact:

- `suite/env` holds what PHPBench's environment providers record: the PHP version, its extensions and whether Xdebug is
  loaded (`php`), OPcache (`opcache`), the operating system (`uname`), the branch and commit (`vcs`), the sampled speed
  of the machine (`sampler`), and on Linux, as the job runs, the system load (`unix-sysload`);
- `variant/parameter-set` holds, on each subject of `SamlValidationBench` and `IdTokenValidationBench`, the version of
  each package its times depend on, read from Composer's installed versions by `BenchApplication::versions()`. Its name
  repeats them, so the console's `aggregate` report shows them in its `set` column. `composer.lock` is not committed, so
  the commit alone does not give them.

`AddressPolicyBench` depends on no package, so PHP's version is all it needs recorded.

## Success Path

1. A change to an operation that sends another statement fails its budget, on every engine, in CI.
2. Its author reads the statements the failure lists, and either removes the statement or explains it in the note of
   that operation and moves the number with the explanation.
3. On a schedule, or when asked, the `benchmarks` job records the times and what they were measured on.

## Failure / Edge Cases

- A budget on a shared counters connection counts the counters' statements with the rest. Only `useSeparateCounters()`
  splits them; on a server it moves the table, since both connections reach one database.
- A kind's `limit` differs across the probe and a page, and only the probe is `limit 1`.
- A withdrawal that deleted nothing raises no links version. Whether a batch would come to that by a race is the
  concurrency suite's to show; the budget calls `ReservationWithdrawal::expired()` directly.
- A subject answers what it validated, which PHPBench ignores and `BenchmarksRunTest` asserts.
- PHPBench reads a bench's doc comments beside its attributes, and skips a file holding a tag it does not know with only
  a warning, so the run stays green having measured nothing. A bench's doc comments therefore carry no tag of a coding
  standard, and `BenchmarksRunTest` reads each through PHPBench's own reader.

## Implementation Anchors

- `tests/Performance/PerformanceContractTestCase.php`
- `benchmarks/Support/BenchApplication.php`
- `benchmarks/Protocols/SamlValidationBench.php`, `benchmarks/Protocols/IdTokenValidationBench.php`
- `benchmarks/Fetching/AddressPolicyBench.php`, `benchmarks/Runtime/ServiceProviderBench.php`
- `phpbench.json`, and the `bench` and `bench:ci` scripts of `composer.json`

## Authoritative Tests

- `tests/Performance/FullFlowQueryBudgetTest.php`
- `tests/Performance/ReauthenticationQueryBudgetTest.php`
- `tests/Performance/OperationsQueryBudgetTest.php`
- `tests/Performance/ExpiryReportQueryBudgetTest.php`
- `tests/Performance/QueryGrowthTest.php`
- `tests/Unit/Benchmarks/BenchmarksRunTest.php`

## Change Triggers

Revisit this note when:

- an operation is added, or a stage of a flow reads or writes another table;
- `Pruner`, `ExpiryReport`, `MetadataRefresher` or `DomainRechecker` changes what it pages by, or its page size;
- a protocol's library changes, so what a bench's `provideVersions()` names changes with it;
- a bench is added, which `BenchmarksRunTest` then requires an expectation of.
